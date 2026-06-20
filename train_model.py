import os
import re
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split, RandomizedSearchCV, StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer, HashingVectorizer, TfidfTransformer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.metrics import classification_report, accuracy_score, f1_score


def clean_text(text):
    text = str(text)
    text = text.lower()
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"https?://\S+|www\.[^\s]+", " ", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def load_data(csv_path):
    df = pd.read_csv(csv_path)

    if "Unnamed: 0" in df.columns:
        df = df.drop(columns=["Unnamed: 0"])

    df = df.rename(columns={"Email Text": "text", "Email Type": "label"})
    df = df.dropna(subset=["text", "label"])

    label_map = {"Safe Email": 0, "Phishing Email": 1}
    df = df[df["label"].isin(label_map)].copy()
    df["label"] = df["label"].map(label_map)
    df["text"] = df["text"].apply(clean_text)

    X = df["text"].values
    y = df["label"].values
    return X, y


def build_vectorizer(use_hashing=False):
    if use_hashing:
        hv = HashingVectorizer(
            n_features=2 ** 18,
            alternate_sign=False,
            ngram_range=(1, 2),
            stop_words="english",
            token_pattern=r"(?u)\b\w+\b",
        )
        return (hv, TfidfTransformer())

    word_vectorizer = TfidfVectorizer(
        stop_words="english",
        ngram_range=(1, 2),
        max_df=0.85,
        min_df=3,
        max_features=15000,
        sublinear_tf=True,
        token_pattern=r"(?u)\b\w+\b",
    )

    char_vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_df=0.85,
        min_df=3,
        max_features=6000,
        sublinear_tf=True,
    )

    return FeatureUnion([("word", word_vectorizer), ("char", char_vectorizer)])


def build_models(vectorizer):
    return [
        (
            "Logistic Regression",
            Pipeline(
                [
                    ("vectorizer", vectorizer),
                    (
                        "classifier",
                        LogisticRegression(
                            solver="saga",
                            penalty="elasticnet",
                            max_iter=2000,
                            class_weight="balanced",
                            random_state=42,
                            n_jobs=-1,
                        ),
                    ),
                ]
            ),
            {
                "classifier__C": [0.1, 0.5, 1.0],
                "classifier__l1_ratio": [0.0, 0.5, 1.0],
            },
        ),
        (
            "Random Forest",
            Pipeline(
                [
                    ("vectorizer", vectorizer),
                    (
                        "classifier",
                        RandomForestClassifier(
                            class_weight="balanced",
                            random_state=42,
                            n_jobs=-1,
                        ),
                    ),
                ]
            ),
            {
                "classifier__n_estimators": [100, 150],
                "classifier__max_depth": [None, 20],
            },
        ),
    ]


def build_fast_pipeline_components():
    hv = HashingVectorizer(n_features=2 ** 18, alternate_sign=False, ngram_range=(1, 2), stop_words="english", token_pattern=r"(?u)\b\w+\b")
    tf = TfidfTransformer()
    clf = SGDClassifier(loss="log_loss", max_iter=1000, tol=1e-3, n_jobs=-1, random_state=42)
    pipeline = Pipeline([("vectorizer", hv), ("tfidf", tf), ("classifier", clf)])
    params = {
        "classifier__alpha": [1e-4, 1e-3, 1e-2],
    }
    return pipeline, params


def evaluate_model(name, grid, X_test, y_test):
    print(f"\n{name} results")
    print("Best params:", grid.best_params_)
    y_pred = grid.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("F1 macro:", f1_score(y_test, y_pred, average="macro"))
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))


def save_models(best_pipeline, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    joblib.dump(best_pipeline, os.path.join(output_dir, "phishing_pipeline.pkl"))
    joblib.dump(best_pipeline.named_steps["classifier"], os.path.join(output_dir, "phishing_model.pkl"))
    joblib.dump(best_pipeline.named_steps["vectorizer"], os.path.join(output_dir, "vectorizer.pkl"))


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Train phishing detection models")
    parser.add_argument("--fast", action="store_true", help="Train faster Hashing+SGD pipeline and save as fast artifacts")
    args = parser.parse_args()

    project_dir = os.path.dirname(__file__)
    csv_path = os.path.join(project_dir, "Phishing_Email.csv")
    output_dir = os.path.join(project_dir, "models")

    X, y = load_data(csv_path)
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    cv = StratifiedKFold(n_splits=4, shuffle=True, random_state=42)

    if args.fast:
        print("Training fast HashingVectorizer + SGD pipeline")
        pipeline, params = build_fast_pipeline_components()
        search = RandomizedSearchCV(
            pipeline,
            param_distributions=params,
            n_iter=3,
            cv=cv,
            scoring="f1_macro",
            refit=True,
            n_jobs=-1,
            random_state=42,
            verbose=1,
        )
        search.fit(X_train, y_train)
        evaluate_model("Fast SGD", search, X_test, y_test)

        best_pipeline = search.best_estimator_
        os.makedirs(output_dir, exist_ok=True)
        joblib.dump(best_pipeline, os.path.join(output_dir, "phishing_pipeline_fast.pkl"))
        joblib.dump(best_pipeline.named_steps["classifier"], os.path.join(output_dir, "phishing_model_fast.pkl"))
        # HashingVectorizer is stateless; save the pipeline for inference
        print(f"Saved fast model artifacts to {output_dir}")
        return

    # default full training (TF-IDF based)
    vectorizer = build_vectorizer()
    models = build_models(vectorizer)

    best_score = -1
    best_pipeline = None
    best_name = None

    for model_name, pipeline, params in models:
        print(f"Training {model_name}")
        search = RandomizedSearchCV(
            pipeline,
            param_distributions=params,
            n_iter=4,
            cv=cv,
            scoring="f1_macro",
            refit=True,
            n_jobs=-1,
            random_state=42,
            verbose=1,
        )
        search.fit(X_train, y_train)
        evaluate_model(model_name, search, X_test, y_test)

        test_f1 = f1_score(y_test, search.predict(X_test), average="macro")
        if test_f1 > best_score:
            best_score = test_f1
            best_pipeline = search.best_estimator_
            best_name = model_name

    print(f"\nSelected best model: {best_name} with F1 macro {best_score:.4f}")
    save_models(best_pipeline, output_dir)
    print(f"Saved best model artifacts to {output_dir}")


if __name__ == "__main__":
    main()

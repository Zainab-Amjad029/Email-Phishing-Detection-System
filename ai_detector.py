import logging
import os
import re
import json

from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO)

try:
    import openai
except ImportError:
    openai = None

try:
    import requests
except Exception:
    requests = None

try:
    from transformers import pipeline
except ImportError:
    pipeline = None


def _parse_openai_response(text):
    text = text.strip()
    label = None
    confidence = None

    # Prefer JSON payload if the model returns structured output.
    try:
        parsed = json.loads(text)
        label = parsed.get("label") or parsed.get("prediction")
        confidence = parsed.get("confidence")
    except Exception:
        pass

    if not label:
        label_match = re.search(r"\b(PHISHING|SAFE)\b", text, re.IGNORECASE)
        if label_match:
            label = label_match.group(1).upper()

    if confidence is None:
        conf_match = re.search(r"(\d+(?:\.\d+)?)\s*%", text)
        if conf_match:
            confidence = float(conf_match.group(1))

    if label and confidence is not None:
        return label, min(max(confidence, 0.0), 100.0)
    if label:
        return label, 75.0
    return None, None


def _ai_classify_openai(text):
    if openai is None:
        return None

    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GROQ_API_KEY")
    if not api_key:
        logging.warning("OPENAI_API_KEY or GROQ_API_KEY is missing or not loaded.")
        return None

    openai.api_key = api_key

    api_base = os.getenv("OPENAI_API_BASE") or os.getenv("GROQ_API_BASE")
    if api_base:
        openai.api_base = api_base
    elif os.getenv("GROQ_API_KEY"):
        openai.api_base = "https://api.groq.cloud/v1"
    prompt = (
        "You are an email security assistant. "
        "Classify the following email as either PHISHING or SAFE. "
        "Respond with a JSON object containing 'label' and 'confidence' (0-100).\n\n"
        f"Email:\n{text}\n"
    )

    try:
        # determine whether the installed openai package uses the new client
        use_new_client = False
        try:
            ver = getattr(openai, "__version__", None)
            if ver is not None:
                from packaging import version as _v
                if _v.parse(ver) >= _v.parse("1.0.0"):
                    use_new_client = True
        except Exception:
            use_new_client = False

        if use_new_client:
            # pass api_key and api_base to the new OpenAI client so alternate providers work
            # new client accepts api_key; api_base is set on the module above
            client = openai.OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=150,
            )
            try:
                content = response.choices[0].message.content
            except Exception:
                content = str(response)
        else:
            # older interface
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=150,
            )
            content = response.choices[0].message.content
    except Exception as exc:
        logging.warning("OpenAI classification failed: %s", exc)
        return None
    label, confidence = _parse_openai_response(content)
    if label:
        return {
            "label": label,
            "confidence": confidence,
            "source": "openai",
            "raw": content,
        }
    return None


_transformer_classifier = None

def _get_transformer_classifier():
    global _transformer_classifier
    if _transformer_classifier is None:
        if pipeline is None:
            return None
        try:
            _transformer_classifier = pipeline(
                "zero-shot-classification",
                model="facebook/bart-large-mnli"
            )
        except Exception:
            return None
    return _transformer_classifier


def _ai_classify_transformers(text):
    classifier = _get_transformer_classifier()
    if classifier is None:
        return None

    try:
        result = classifier(
            sequences=text,
            candidate_labels=["PHISHING", "SAFE"],
            hypothesis_template="This email is {}.",
            multi_class=False,
        )
    except Exception:
        return None

    label = result.get("labels", [None])[0]
    score = result.get("scores", [0.0])[0]
    if label is None:
        return None

    return {
        "label": label.upper(),
        "confidence": float(score * 100),
        "source": "transformers",
        "raw": result,
    }


def _ai_classify_groq(text):
    """Call Groq Cloud REST API directly using GROQ_API_KEY and GROQ_API_BASE.
    This attempts a chat/completions-style request and parses common response shapes.
    """
    if requests is None:
        logging.info("requests library not available for Groq calls")
        return None

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return None

    base = os.getenv("GROQ_API_BASE", "https://api.groq.cloud/v1")
    model = os.getenv("GROQ_MODEL", "gpt-3o-mini")

    url = base.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": (
            "You are an email security assistant. Classify the following email as either PHISHING or SAFE. "
            "Respond with a JSON object containing 'label' and 'confidence' (0-100).\n\n" + text
        )}],
        "temperature": 0,
        "max_tokens": 150,
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logging.warning("Groq classification failed: %s", exc)
        return None

    # Try common shapes
    content = None
    try:
        content = data.get("choices", [])[0].get("message", {}).get("content")
    except Exception:
        pass
    if not content:
        try:
            content = data.get("choices", [])[0].get("text")
        except Exception:
            pass

    if not content:
        content = json.dumps(data)

    label, confidence = _parse_openai_response(content)
    if label:
        return {"label": label, "confidence": confidence, "source": "groq", "raw": content}
    return None


def ai_detect_email(text):
    if not text or not text.strip():
        return None

    # Prefer Groq if configured
    if os.getenv("GROQ_API_KEY"):
        detection = _ai_classify_groq(text)
        if detection:
            return detection
        # If Groq is configured but fails, do not attempt OpenAI with a Groq key.
        logging.info("Groq configured but classification failed; skipping OpenAI fallback.")
        detection = _ai_classify_transformers(text)
        if detection:
            return detection
        return None

    detection = _ai_classify_openai(text)
    if detection:
        return detection

    detection = _ai_classify_transformers(text)
    if detection:
        return detection

    return None

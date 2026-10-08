# מסמך אפיון ארכיטקטורה ודרישות מלא – WebTech Inspector (שלב 1)

## חלק ב' – ארכיטקטורת המודלים ו-OOP (`models.py`)

### 1. היררכיית `Endpoint`

#### 1.1 `Endpoint` – מחלקת אב
* **מאפיינים אבסטרקטיים מחייבים:**
  * `endpoint_id: str`
  * `raw_content: str`
  * `matched_signatures: set[Signature]` – מנוהל כ-`set` למניעת כפילויות.
* **מתודות:**
  * `add_signature(self, signature: Signature) -> None`: הוספת חתימה ל-`matched_signatures` בשימוש ב-`self.matched_signatures.add(signature)`.
  * `tag(self, signatures: list[Signature]) -> list[Signature]`: 
    * מריצה סינון חכם (Smart Filtering) לפי סוג ה-Endpoint.
    * מפעילה `signature.match(self)`. אם נכון – מוסיפה ל-`matched_signatures`, מחלצת גרסה ע"י `signature.extract_version(self)`, ומחזירה את רשימת התיוגים שנמצאו.

#### 1.2 `ContentEndpoint(Endpoint)` – יורשת 1
* **מאפיינים נוספים:**
  * `path: str`
  * `status_code: int`
  * `content_type: str`
* **אימותי נתונים (Strict Validation):**
  * `status_code`: חייב להיות אחד מתוך הרשימה הנסגרת: `[200, 500, 401, 404, 403]`. ערך אחר יזרוק `ValueError`.
  * `content_type`: חייב להיות אחד מתוך הרשימה: `['JSON', 'HTML', 'JS', 'CSS']`. ערך אחר יזרוק `ValueError`.
* **Computed Property:**
  * `@property is_successful(self) -> bool`: מחזיר `True` במידה ו-`status_code == 200`.
* **בנאי אלטרנטיבי:** `@classmethod from_dict(cls, data: dict)`.

#### 1.3 `MetaDataEndpoint(Endpoint)` – יורשת 2
* **תפקיד:** מייצגת מידע תיאורי/מקדים על האתר/המערכת.
* **מאפיינים:** יורשת `endpoint_id` ו-`raw_content` ללא צורך בפרמטרים נוספים או אימותי HTTP.
* **בנאי אלטרנטיבי:** `@classmethod from_dict(cls, data: dict)`.

---

### 2. מחלקת `ScanTarget` (Composition & Scope Registry)

* **מאפיינים:**
  * `target_id: str`
  * `uri: str`
  * `endpoints: list[Endpoint]` (קשר הרכבה – Composition)
  * `created_at: str`
* **ניהול Scope ואימות הייחודיות (`_registry`):**
  * ניהול `_registry = set()` ברמת המחלקה.
  * בעת יצירת מופע חדש: אימות ש-`uri` אינו מחרוזת ריקה (`isinstance(uri, str)` ו-`len(uri.strip()) > 0`).
  * בדיקה ש-`uri` אינו קיים כבר ב-`_registry`. אם קיים ב-Scope – הנפת `ValueError`.
* **מתודות הרכבה:**
  * `add_endpoint(endpoint: Endpoint)`
  * `remove_endpoint(endpoint_id: str) -> bool`
  * `get_successful_endpoints() -> list[ContentEndpoint]`
  * `get_metadata_endpoints() -> list[MetaDataEndpoint]`
  * `tag_all(self, signatures: list[Signature]) -> dict`: עוברת על `self.endpoints`, מפעילה `endpoint.tag(signatures)`, ומחזירה סיכום מרוכז.
* **מתודות מיוחדות ב-Python:**
  * `__len__(self) -> int`: מחזירה את כמות ה-Endpoints ב-Target (`len(self.endpoints)`).
  * `@classmethod summary_stats(cls, targets: list['ScanTarget']) -> dict`: מחשבת נתונים מרוכזים בשימוש מפורש ב-`len(target)` עבור כל Target:
    1. כמות TARGETs כוללת.
    2. ממוצע ENDPOINTs ל-Target.
    3. מקסימום ENDPOINTs ל-Target.
    4. מינימום ENDPOINTs ל-Target.
    5. כמות ה-TARGETs עם 0 ENDPOINTs (`len(target) == 0`).
  * `@classmethod from_dict(cls, data: dict)`.

---

### 3. היררכיית `Signature` (Polymorphism)

#### 3.1 `Signature(ABC)` – מחלקת אב אבסטרקטית
* **מאפיינים:** `signature_id: str`, `tech_name: str`, `category: str`.
* **מתודות אבסטרקטיות:**
  * `@abstractmethod match(self, endpoint: Endpoint) -> bool`
  * `@abstractmethod extract_version(self, endpoint: Endpoint) -> str`

#### 3.2 `RegexSignature(Signature)` – יורשת 1
* **מאפיינים נוספים:** `match_pattern: str` (חובה), `version_pattern: str | None` (רשות).
* **מימוש מתודות:**
  * `match(endpoint: Endpoint) -> bool`: מריצה `re.search(self.match_pattern, endpoint.raw_content)`.
  * `extract_version(endpoint: Endpoint) -> str`: מריצה `re.search` עם `version_pattern` ומחזירה את הגרסה שנמצאה.

#### 3.3 `PackageSignature(Signature)` – יורשת 2
* **מאפיינים נוספים:** `package_name: str`, `target_file: str = "package.json"`.
* **מימוש מתודות:**
  * `match(endpoint: Endpoint) -> bool`: מפענחת JSON ב-`ContentEndpoint` ומחפשת את `package_name` ב-`dependencies` / `devDependencies`.
  * `extract_version(endpoint: Endpoint) -> str`: מחזירה את מחרוזת הגרסה שנרשמה ב-JSON עבור החבילה.

---

### 4. מחלקת `Insight` (תובנות וחולשות)

* **מאפיינים:** `insight_id: str`, `cve_id: str | None`, `severity: int` (טווח 1–4), `description: str`, `recommendation: str`, `tech_name: str | None`.
* **אימות נתונים:** אימות ש-`severity` בטווח 1 עד 4 בלבד (`ValueError` אם לא).
* **מתודות וכלים ב-Python:**
  * **`__lt__(self, other: 'Insight') -> bool`**: מוגדר עבור **תור עדיפויות (`heapq`)** – דרגת חומרה קריטית יותר (`1 < 4`) קודמת בתור. במקרה של שוויון, השוואה משנית לפי `cve_id`.
  * `@property is_critical(self) -> bool`: מחזיר `True` במידה ו-`severity == 1`.
  * `@staticmethod normalize_cve(cve_str: str) -> str`: מנרמלת מחרוזת CVE (למשל `cve-2023-1234` ⬅️ `CVE-2023-1234`).
  * `@classmethod from_dict(cls, data: dict)`.
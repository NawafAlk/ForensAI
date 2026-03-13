"""
ForensAI - Natural Language Query Engine
=========================================
Translates natural language questions into filter predicates for searching
forensic artifacts using the Groq AI API.

Provides:
- NL-to-predicate translation via Groq AI
- Predicate-based file filtering
- Autocomplete suggestions for common forensic queries
- LRU caching for repeated queries
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FilterPredicate:
    """
    A single filter condition for matching forensic artifacts.

    Attributes:
        field: The artifact field to filter on
               (e.g., "name", "size", "created", "modified", "accessed", "type", "path")
        operator: The comparison operator
                  (e.g., "contains", "equals", "gt", "lt", "gte", "lte", "regex", "in")
        value: The value to compare against
        negate: If True, invert the match (logical NOT)
    """
    field: str
    operator: str
    value: Any
    negate: bool = False


@dataclass
class QueryResult:
    """
    Result of translating a natural language query into filter predicates.

    Attributes:
        predicates: List of FilterPredicate objects to apply
        explanation: Human-readable explanation of what the query does
        confidence: Confidence score (0.0 to 1.0) in the translation accuracy
        original_query: The original natural language query string
    """
    predicates: List[FilterPredicate]
    explanation: str
    confidence: float
    original_query: str


class NLQueryEngine:
    """
    Natural Language Query Engine for forensic artifact search.

    Translates natural language questions (e.g., "show me large executables in temp folders")
    into structured FilterPredicate objects that can be applied to filter file listings.
    Uses the Groq AI API for NL understanding and caches results for performance.
    """

    SUGGESTION_TEMPLATES = [
        "show me executables",
        "show me all .exe files",
        "show me all .dll files",
        "files modified today",
        "files modified in the last 24 hours",
        "files modified in the last 7 days",
        "files created today",
        "large files over 100MB",
        "large files over 1GB",
        "small files under 1KB",
        "hidden files",
        "hidden executables",
        "recently deleted files",
        "files in temp folders",
        "files in the recycle bin",
        "files in downloads folder",
        "files in AppData",
        "files in System32",
        "files with double extensions",
        "encrypted files",
        "compressed archives",
        "image files",
        "document files",
        "PDF files",
        "Office documents",
        "database files",
        "log files",
        "configuration files",
        "scripts and batch files",
        "files with suspicious names",
        "files larger than 500MB",
        "files modified before 2020",
        "files created after a specific date",
        "empty files",
        "files with no extension",
        "files containing password in the name",
        "files in user profile directories",
        "prefetch files",
        "link files (.lnk)",
        "registry hive files",
        "browser history files",
        "email database files",
        "files modified between two dates",
        "executable files outside system directories",
        "recently accessed files",
        "files with .tmp extension",
        "zip and rar archives",
    ]

    FILE_SCHEMA = {
        "name": "Filename including extension (e.g., 'document.pdf', 'svchost.exe')",
        "size": "File size in bytes (integer)",
        "type": "File type or category (e.g., 'file', 'directory', 'executable', 'document')",
        "created": "Creation timestamp (ISO 8601 string, e.g., '2024-01-15T10:30:00')",
        "modified": "Last modification timestamp (ISO 8601 string)",
        "accessed": "Last access timestamp (ISO 8601 string)",
        "path": "Full file path within the disk image (e.g., '/Users/john/Documents/report.pdf')",
    }

    VALID_FIELDS = {"name", "size", "type", "created", "modified", "accessed", "path"}
    VALID_OPERATORS = {"contains", "equals", "gt", "lt", "gte", "lte", "regex", "in",
                       "startswith", "endswith"}

    def __init__(self):
        """
        Initialize the NL Query Engine.

        Sets up the LRU cache for query results and loads the AI service
        for Groq API access.
        """
        self._cache: Dict[str, QueryResult] = {}
        self._cache_maxsize = 200
        self._ai_service = None

    @property
    def ai_service(self):
        """Lazy-load the AI service singleton."""
        if self._ai_service is None:
            try:
                from managers.ai_service import get_ai_service
                self._ai_service = get_ai_service()
            except ImportError:
                self._ai_service = None
        return self._ai_service

    def translate_query(self, query: str) -> QueryResult:
        """
        Translate a natural language query into filter predicates using Groq AI.

        Args:
            query: Natural language question, e.g., "find all executables in temp folders"

        Returns:
            QueryResult with predicates, explanation, and confidence score.
            On error, returns a QueryResult with empty predicates and an
            explanation describing the failure.
        """
        if not query or not query.strip():
            return QueryResult(
                predicates=[],
                explanation="Empty query provided.",
                confidence=0.0,
                original_query=query or ""
            )

        normalized = query.strip().lower()

        if normalized in self._cache:
            return self._cache[normalized]

        if self.ai_service is None or not self.ai_service.api_key:
            return QueryResult(
                predicates=[],
                explanation="Error: AI service not available. Please configure your Groq API key in Options > API Keys.",
                confidence=0.0,
                original_query=query
            )

        prompt = self._build_prompt(query)

        try:
            response = self.ai_service._query_groq(
                prompt,
                interaction_purpose="nl_query_translation",
                artifact_id="",
                artifact_name="",
                analysis_type="file_analysis"
            )

            result = self._parse_response(response, query)

            if len(self._cache) >= self._cache_maxsize:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            self._cache[normalized] = result

            return result

        except Exception as e:
            return QueryResult(
                predicates=[],
                explanation=f"Error translating query: {str(e)}",
                confidence=0.0,
                original_query=query
            )

    def apply_predicates(self, files: List[Dict], predicates: List[FilterPredicate]) -> List[Dict]:
        """
        Filter a list of file dictionaries using the given predicates.

        All predicates are combined with AND logic -- a file must match every
        predicate to be included in the results.

        Args:
            files: List of file metadata dictionaries with keys matching the schema
                   (name, size, type, created, modified, accessed, path).
            predicates: List of FilterPredicate objects to apply.

        Returns:
            Filtered list of file dictionaries that match all predicates.
        """
        if not predicates:
            return files

        results = []
        for file_dict in files:
            if self._matches_all_predicates(file_dict, predicates):
                results.append(file_dict)
        return results

    def get_suggestions(self, partial: str) -> List[str]:
        """
        Return autocomplete suggestions based on a partial query string.

        Matches against a curated list of common forensic search queries.
        Returns up to 10 suggestions sorted by relevance (prefix matches first,
        then substring matches).

        Args:
            partial: Partial query string typed by the user.

        Returns:
            List of matching suggestion strings (up to 10).
        """
        if not partial or not partial.strip():
            return self.SUGGESTION_TEMPLATES[:10]

        partial_lower = partial.strip().lower()
        prefix_matches = []
        substring_matches = []

        for suggestion in self.SUGGESTION_TEMPLATES:
            suggestion_lower = suggestion.lower()
            if suggestion_lower.startswith(partial_lower):
                prefix_matches.append(suggestion)
            elif partial_lower in suggestion_lower:
                substring_matches.append(suggestion)

        partial_words = partial_lower.split()
        if len(partial_words) > 1:
            for suggestion in self.SUGGESTION_TEMPLATES:
                suggestion_lower = suggestion.lower()
                if suggestion not in prefix_matches and suggestion not in substring_matches:
                    if all(word in suggestion_lower for word in partial_words):
                        substring_matches.append(suggestion)

        combined = prefix_matches + substring_matches
        return combined[:10]

    def _build_prompt(self, query: str) -> str:
        """
        Build the system prompt sent to Groq AI for NL-to-predicate translation.

        Describes the forensic file schema, available filter operators, and the
        expected JSON response format.

        Args:
            query: The user's natural language query.

        Returns:
            Formatted prompt string for the AI model.
        """
        schema_desc = "\n".join(
            f"  - {field}: {desc}" for field, desc in self.FILE_SCHEMA.items()
        )

        prompt = f"""You are a forensic search query translator for a digital forensics application.

Your task is to translate a natural language question about files in a disk image into
a structured JSON filter specification.

=== FILE SCHEMA ===
The files have these fields:
{schema_desc}

=== AVAILABLE OPERATORS ===
  - "contains": field value contains the string (case-insensitive, for string fields)
  - "equals": exact match (case-insensitive for strings, exact for numbers)
  - "gt": greater than (for numeric fields like size, or date comparisons)
  - "lt": less than (for numeric fields like size, or date comparisons)
  - "gte": greater than or equal to
  - "lte": less than or equal to
  - "regex": regular expression match (for string fields)
  - "in": field value is one of a list of values
  - "startswith": field value starts with the string
  - "endswith": field value ends with the string

=== SIZE REFERENCE ===
  - 1 KB = 1024 bytes
  - 1 MB = 1048576 bytes
  - 1 GB = 1073741824 bytes

=== DATE REFERENCE ===
  - Use ISO 8601 format for dates: "YYYY-MM-DDTHH:MM:SS"
  - "today" means {datetime.now().strftime('%Y-%m-%d')}
  - For relative dates, calculate from today's date

=== COMMON FILE EXTENSIONS ===
  - Executables: .exe, .dll, .sys, .com, .bat, .cmd, .ps1, .vbs, .js, .wsf, .msi
  - Documents: .doc, .docx, .xls, .xlsx, .ppt, .pptx, .pdf, .rtf, .txt
  - Archives: .zip, .rar, .7z, .tar, .gz, .bz2
  - Images: .jpg, .jpeg, .png, .gif, .bmp, .tiff, .svg
  - Databases: .db, .sqlite, .mdb, .accdb
  - Logs: .log, .evtx, .evt
  - System: .lnk, .pf, .dat, .ini, .reg

=== RESPONSE FORMAT ===
Respond with ONLY a valid JSON object in this exact format (no other text):
{{
    "predicates": [
        {{
            "field": "<field_name>",
            "operator": "<operator>",
            "value": <value>,
            "negate": false
        }}
    ],
    "explanation": "<human-readable explanation of what this query searches for>",
    "confidence": <0.0 to 1.0>
}}

Notes:
- Use multiple predicates for complex queries (they are combined with AND logic).
- For "files NOT in X", set "negate": true on that predicate.
- For extension matching, use the "name" field with "endswith" operator.
- For path-based filtering, use the "path" field with "contains" operator.
- Confidence should reflect how certain you are about the translation.
- Keep the explanation concise (1-2 sentences).

=== USER QUERY ===
{query}
"""
        return prompt

    def _parse_response(self, response: str, original_query: str) -> QueryResult:
        """
        Parse the Groq AI response into a QueryResult object.

        Extracts the JSON from the response text, validates the predicates,
        and constructs FilterPredicate objects.

        Args:
            response: Raw response string from the Groq AI API.
            original_query: The original user query for inclusion in the result.

        Returns:
            QueryResult with parsed predicates, or a fallback result on parse failure.
        """
        if response.startswith("Error:"):
            return QueryResult(
                predicates=[],
                explanation=response,
                confidence=0.0,
                original_query=original_query
            )

        try:
            json_str = response.strip()

            if "```json" in json_str:
                json_str = json_str.split("```json", 1)[1]
                json_str = json_str.split("```", 1)[0]
            elif "```" in json_str:
                json_str = json_str.split("```", 1)[1]
                json_str = json_str.split("```", 1)[0]

            json_match = re.search(r'\{[\s\S]*\}', json_str)
            if json_match:
                json_str = json_match.group()

            data = json.loads(json_str)

            predicates = []
            raw_predicates = data.get("predicates", [])
            for pred_data in raw_predicates:
                field_name = str(pred_data.get("field", "")).strip().lower()
                operator = str(pred_data.get("operator", "")).strip().lower()
                value = pred_data.get("value")
                negate = bool(pred_data.get("negate", False))

                if field_name not in self.VALID_FIELDS:
                    continue
                if operator not in self.VALID_OPERATORS:
                    continue
                if value is None:
                    continue

                predicates.append(FilterPredicate(
                    field=field_name,
                    operator=operator,
                    value=value,
                    negate=negate
                ))

            explanation = data.get("explanation", "Query translated successfully.")
            confidence = float(data.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))

            return QueryResult(
                predicates=predicates,
                explanation=explanation,
                confidence=confidence,
                original_query=original_query
            )

        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            return QueryResult(
                predicates=[],
                explanation=f"Failed to parse AI response: {str(e)}. Raw response: {response[:200]}",
                confidence=0.0,
                original_query=original_query
            )

    def _matches_all_predicates(self, file_dict: Dict, predicates: List[FilterPredicate]) -> bool:
        """
        Check if a file dictionary matches all the given predicates.

        Args:
            file_dict: A single file metadata dictionary.
            predicates: List of FilterPredicate objects (AND logic).

        Returns:
            True if the file matches all predicates, False otherwise.
        """
        for predicate in predicates:
            match = self._evaluate_predicate(file_dict, predicate)
            if predicate.negate:
                match = not match
            if not match:
                return False
        return True

    def _evaluate_predicate(self, file_dict: Dict, predicate: FilterPredicate) -> bool:
        """
        Evaluate a single predicate against a file dictionary.

        Handles string comparisons (case-insensitive), numeric comparisons,
        date comparisons, and regex matching.

        Args:
            file_dict: A single file metadata dictionary.
            predicate: The FilterPredicate to evaluate.

        Returns:
            True if the predicate matches (before negate is applied), False otherwise.
        """
        field_value = file_dict.get(predicate.field)
        if field_value is None:
            return False

        op = predicate.operator
        target = predicate.value

        try:
            if op == "contains":
                return str(target).lower() in str(field_value).lower()

            elif op == "equals":
                if isinstance(field_value, (int, float)):
                    return field_value == self._to_number(target)
                return str(field_value).lower() == str(target).lower()

            elif op == "startswith":
                return str(field_value).lower().startswith(str(target).lower())

            elif op == "endswith":
                return str(field_value).lower().endswith(str(target).lower())

            elif op == "regex":
                return bool(re.search(str(target), str(field_value), re.IGNORECASE))

            elif op == "in":
                if isinstance(target, list):
                    field_lower = str(field_value).lower()
                    return any(field_lower == str(t).lower() for t in target)
                return False

            elif op in ("gt", "lt", "gte", "lte"):
                return self._compare_values(field_value, target, op)

        except (ValueError, TypeError, re.error):
            return False

        return False

    def _compare_values(self, field_value: Any, target: Any, op: str) -> bool:
        """
        Perform a comparison (gt, lt, gte, lte) between field_value and target.

        Handles numeric values and ISO 8601 date strings.

        Args:
            field_value: The value from the file dictionary.
            target: The target value from the predicate.
            op: The comparison operator ("gt", "lt", "gte", "lte").

        Returns:
            True if the comparison holds, False otherwise.
        """
        try:
            num_field = self._to_number(field_value)
            num_target = self._to_number(target)
            if num_field is not None and num_target is not None:
                if op == "gt":
                    return num_field > num_target
                elif op == "lt":
                    return num_field < num_target
                elif op == "gte":
                    return num_field >= num_target
                elif op == "lte":
                    return num_field <= num_target
        except (ValueError, TypeError):
            pass

        try:
            date_field = self._to_datetime(field_value)
            date_target = self._to_datetime(target)
            if date_field is not None and date_target is not None:
                if op == "gt":
                    return date_field > date_target
                elif op == "lt":
                    return date_field < date_target
                elif op == "gte":
                    return date_field >= date_target
                elif op == "lte":
                    return date_field <= date_target
        except (ValueError, TypeError):
            pass

        try:
            str_field = str(field_value).lower()
            str_target = str(target).lower()
            if op == "gt":
                return str_field > str_target
            elif op == "lt":
                return str_field < str_target
            elif op == "gte":
                return str_field >= str_target
            elif op == "lte":
                return str_field <= str_target
        except (ValueError, TypeError):
            pass

        return False

    @staticmethod
    def _to_number(value: Any) -> Optional[float]:
        """
        Convert a value to a numeric type if possible.

        Args:
            value: The value to convert.

        Returns:
            Float representation, or None if conversion fails.
        """
        if isinstance(value, (int, float)):
            return float(value)
        try:
            return float(value)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _to_datetime(value: Any) -> Optional[datetime]:
        """
        Convert a value to a datetime object if possible.

        Supports datetime objects directly, and ISO 8601 formatted strings
        with various levels of precision.

        Args:
            value: The value to convert.

        Returns:
            datetime object, or None if conversion fails.
        """
        if isinstance(value, datetime):
            return value
        if not isinstance(value, str):
            return None

        formats = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue

        return None

    def clear_cache(self):
        """Clear the query translation cache."""
        self._cache.clear()


_nl_query_engine: Optional[NLQueryEngine] = None


def get_nl_query_engine() -> NLQueryEngine:
    """Get the singleton NLQueryEngine instance."""
    global _nl_query_engine
    if _nl_query_engine is None:
        _nl_query_engine = NLQueryEngine()
    return _nl_query_engine

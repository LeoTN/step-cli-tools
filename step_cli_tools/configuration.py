# --- Standard library imports ---
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# --- Third-party imports ---
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

# --- Local application imports ---
from .common import *
from .validators import *

__all__ = [
    "config",
    "check_and_repair_config_file",
    "show_config_operations",
]


yaml = YAML()
yaml.indent(mapping=2, sequence=4, offset=2)
yaml.preserve_quotes = True


class Configuration:
    def __init__(self, file_location: str, schema: dict, autosave: bool = True):
        """
        Initialize Configuration object. Note, that the load() method MUST be called manually once.

        Args:
            file_location: Absolute path to the YAML config file.
            schema: Dictionary defining the config schema with types, defaults, validators, and comments.
            autosave: Automatically save after each set() call if True.
        """
        self.file_location = Path(file_location)
        self.file_location.parent.mkdir(parents=True, exist_ok=True)
        self.schema = schema
        self.autosave = autosave
        self._data = CommentedMap()

    # --- File and public API handling ---
    def load(self):
        """Load YAML config and merge defaults into a CommentedMap with comments."""
        if self.file_location.exists():
            try:
                loaded = yaml.load(self.file_location.read_text()) or {}
            except Exception as e:
                console.print(f"[WARNING] Failed to load config: {e}", style="#F9ED69")
                loaded = {}
        else:
            loaded = {}

        self._data = self._build_commented_data(self.schema, loaded)

    def save(self):
        """Save current configuration data to YAML file."""
        try:
            with self.file_location.open("w", encoding="utf-8") as f:
                yaml.dump(self._data, f)
        except (OSError, IOError) as e:
            console.print(
                f"[ERROR] Could not save settings to '{self.file_location}': {e}",
                style="#B83B5E",
            )

    def generate_default(self, overwrite: bool = False):
        """
        Generate a default configuration file from the schema.

        Args:
            overwrite: If True, existing file will be replaced. Otherwise, existing file will be kept.
        """
        try:
            if self.file_location.exists() and not overwrite:
                console.print(
                    f"[WARNING] Config file already exists: {self.file_location}. Use overwrite=True to replace it.",
                    style="#F9ED69",
                )
                return

            # Backup existing file before overwriting
            if self.file_location.exists() and overwrite:
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                backup_path = self.file_location.with_name(
                    f"{self.file_location.stem}_backup_{timestamp}{self.file_location.suffix}"
                )
                shutil.copy2(self.file_location, backup_path)
                console.print(f"[INFO] Created backup before overwrite: {backup_path}")

            # This is a bit akward but the file is technically repaired without keeping any data.
            default_data = self._build_commented_data(
                self.schema, repair_damaged_keys=True, suppress_repair_messages=True
            )

            # Save YAML file
            with self.file_location.open("w", encoding="utf-8") as f:
                yaml.dump(default_data, f)

            console.print(
                f"[INFO] Default configuration file was generated successfully: {self.file_location}",
                style="green",
            )

            # Load the data into memory so it's ready for use
            self._data = default_data

        except Exception as e:
            console.print(
                f"[ERROR] Failed to generate default configuration: {e}",
                style="#B83B5E",
            )

    def get(self, key: str):
        """Retrieve a setting value using dotted key path; fallback to default if missing.

        Args:
            key: Dotted path to the setting (e.g., "network.timeout").

        Returns:
            The current value or the schema default if missing.
        """
        parts = key.split(".")
        data = self._data
        for part in parts:
            if not isinstance(data, dict) or part not in data:
                console.print(
                    f"[WARNING] Failed to extract the value for '{key}' from the configuration file.",
                    style="#F9ED69",
                )
                return self._nested_get_default(parts)
            data = data[part]
        return data

    def set(self, key: str, value):
        """Set a value using a dotted key path, cast to schema type if needed.

        Args:
            key: Dotted path to the setting.
            value: Value to set.
        """
        parts = key.split(".")
        data = self._data

        # Check if key exists in schema
        schema_meta = self._nested_get_meta(parts)
        if not schema_meta:
            console.print(
                f"[WARNING] Key '{key}' does not exist in the config schema. Value '{value}' will still be set.",
                style="#F9ED69",
            )

        # Navigate or create nested dictionaries
        for part in parts[:-1]:
            if part not in data or not isinstance(data[part], dict):
                data[part] = CommentedMap()
            data = data[part]

        # Cast to schema-defined type if applicable
        expected_type = self._nested_get_type(parts)
        if expected_type and not isinstance(value, expected_type):
            try:
                value = expected_type(value)
            except Exception:
                console.print(
                    f"[WARNING] Failed to cast value '{value}' to {expected_type.__name__} for key '{key}'",
                    style="#F9ED69",
                )

        data[parts[-1]] = value

        if self.autosave:
            self.save()

    def repair(self):
        """Restore missing keys and values from the schema and optionally autosave."""
        self._data = self._build_commented_data(
            self.schema, self._data, repair_damaged_keys=True
        )
        if self.autosave:
            self.save()

    def validate(self, key: str | None = None) -> bool:
        """Validate settings against schema validators.

        Args:
            key: Optional dotted key path to validate only that entry.

        Returns:
            True if all checked values are valid, False otherwise.
        """
        if key:
            parts = key.split(".")
            meta = self._nested_get_meta(parts)
            if not meta:
                console.print(f"[WARNING] No schema entry for '{key}'", style="#F9ED69")
                return False

            validator = meta.get("validator")
            validator = self._wrap_validator(meta, validator)

            if not validator:
                return True

            value = self.get(key)
            try:
                if not callable(validator):
                    console.print(
                        f"[WARNING] Validator for '{key}' is not callable: {validator!r}",
                        style="#F9ED69",
                    )
                    return False

                result = validator(value)

            except Exception as e:
                console.print(
                    f"[ERROR] Validator for '{key}' raised an exception: {e}",
                    style="#B83B5E",
                )
                return False

            if result is None:
                return True
            if isinstance(result, str):
                console.print(
                    f"[WARNING] Validation failed for '{key}': {result}",
                    style="#F9ED69",
                )
                return False

            console.print(
                f"[ERROR] Validator for '{key}' returned unsupported value: {result!r}",
                style="#B83B5E",
            )
            return False

        # No specific key -> validate full schema recursively
        return self._validate_recursive(self._data, self.schema, prefix="")

    # --- Internal helpers ---
    def _wrap_validator(self, meta, validator):
        """Wrap validator with schema params if needed.

        Args:
            meta: Schema metadata for the key.
            validator: Original validator function.

        Returns:
            Callable validator with parameters applied if applicable.
        """
        if callable(validator):
            if validator is int_range_validator and "min" in meta and "max" in meta:
                return int_range_validator(meta["min"], meta["max"])
            elif validator is str_allowed_validator and "allowed" in meta:
                return str_allowed_validator(meta["allowed"])
        return validator

    def _validate_recursive(self, data: dict, schema: dict, prefix: str) -> bool:
        """Recursively validate all settings against schema.

        Args:
            data: Current level of config data.
            schema: Schema dict for this level.
            prefix: Dotted path prefix for nested keys.

        Returns:
            True if all values valid, False otherwise.
        """
        ok = True
        for k, meta in schema.items():
            if not isinstance(meta, dict):
                continue

            full_key = f"{prefix}.{k}" if prefix else k

            if "type" not in meta:
                sub_data = data.get(k, {})
                if not isinstance(sub_data, dict):
                    console.print(
                        f"[WARNING] Expected dict at '{full_key}', got {type(sub_data).__name__}",
                        style="#F9ED69",
                    )
                    ok = False
                elif not self._validate_recursive(sub_data, meta, full_key):
                    ok = False
                continue

            validator = meta.get("validator")
            validator = self._wrap_validator(meta, validator)

            if validator:
                try:
                    value = data.get(k, meta.get("default"))

                    if not callable(validator):
                        console.print(
                            f"[WARNING] Validator for '{full_key}' is not callable: {validator!r}",
                            style="#F9ED69",
                        )
                        ok = False
                        continue

                    result = validator(value)
                    if isinstance(result, str):
                        console.print(
                            f"[WARNING] Validation failed for '{full_key}': {result}",
                            style="#F9ED69",
                        )
                        ok = False
                    elif result is not None:
                        console.print(
                            f"[ERROR] Validator for '{full_key}' returned unsupported type: {result!r}",
                            style="#B83B5E",
                        )
                        ok = False

                except Exception as e:
                    console.print(
                        f"[ERROR] Validator for '{full_key}' raised: {e}",
                        style="#B83B5E",
                    )
                    ok = False

        return ok

    def _nested_get_meta(self, keys: list[str]) -> dict | None:
        """Retrieve schema metadata for nested key path."""
        data = self.schema
        for k in keys:
            if not isinstance(data, dict) or k not in data:
                return None
            data = data[k]
        return data if isinstance(data, dict) else None

    def _nested_get_default(self, keys: list[str]):
        """Retrieve default value from schema for nested key path."""
        data = self.schema
        for k in keys:
            if not isinstance(data, dict) or k not in data:
                console.print(
                    f"[WARNING] Missing default for key '{'.'.join(keys)}'",
                    style="#F9ED69",
                )
                return None
            data = data[k]
            if isinstance(data, dict) and "default" in data:
                return data["default"]
        return None

    def _nested_get_type(self, keys: list[str]):
        """Retrieve expected type from schema for nested key path."""
        data = self.schema
        for k in keys:
            if not isinstance(data, dict) or k not in data:
                return None
            data = data[k]
        return data.get("type") if isinstance(data, dict) else None

    def _build_commented_data(
        self,
        schema: dict,
        data: dict | None = None,
        indent: int = 0,
        top_level: bool = True,
        repair_damaged_keys=False,
        suppress_repair_messages=False,
    ) -> CommentedMap:
        """Construct a CommentedMap with schema defaults and YAML comments.

        Args:
            schema: Schema defining keys, types, defaults, validators, and comments.
            data: Optional existing config data to merge.
            indent: Indentation level for YAML comments.
            top_level: True if building top-level mapping.
            repair_damaged_keys: Restore missing keys from schema if True.
            suppress_repair_messages: Suppress log messages from repairing keys if True.

        Returns:
            CommentedMap populated with data and comments.
        """
        data = data or {}
        node = CommentedMap()

        for i, (key, meta) in enumerate(schema.items()):
            if not isinstance(meta, dict):
                continue

            if "type" not in meta:
                child_node = self._build_commented_data(
                    meta,
                    data.get(key, {}),
                    indent + 2,
                    top_level=False,
                    repair_damaged_keys=repair_damaged_keys,
                    suppress_repair_messages=suppress_repair_messages,
                )
                node[key] = child_node
            else:
                node[key] = data.get(key)
                # The data could not be extracted from the config file
                if node[key] is None:
                    if repair_damaged_keys:
                        if not suppress_repair_messages:
                            console.print(
                                f"[INFO] Repairing key '{key}' from config schema."
                            )
                        node[key] = meta.get("default")
                    else:
                        continue

                type_obj = meta.get("type")
                type_name = type_obj.__name__ if type_obj else "unknown"
                default_val = meta.get("default")
                min_val = meta.get("min")
                max_val = meta.get("max")
                allowed = meta.get("allowed")

                if allowed:
                    type_info = f"[{type_name}: allowed: {', '.join(map(str, allowed))} | default: {default_val}]"
                elif min_val is not None or max_val is not None:
                    range_part = ""
                    if min_val is not None and max_val is not None:
                        range_part = f"{min_val} - {max_val}"
                    elif min_val is not None:
                        range_part = f">= {min_val}"
                    elif max_val is not None:
                        range_part = f"<= {max_val}"
                    type_info = f"[{type_name}: {range_part} | default: {default_val}]"
                else:
                    type_info = f"[{type_name} | default: {default_val}]"

                extra_comment = meta.get("comment")
                final_comment = (
                    f"{type_info} - {extra_comment}" if extra_comment else type_info
                )
                node.yaml_set_comment_before_after_key(
                    key, before=final_comment, indent=indent
                )

            # Leave an empty line between top level keys
            if top_level and i > 0:
                node.yaml_set_comment_before_after_key(
                    key,
                    before="\n"
                    + (
                        node.ca.items.get(key)[2].value
                        if node.ca.items.get(key) and node.ca.items.get(key)[2]
                        else ""
                    ),
                    indent=indent,
                )

        return node


def check_and_repair_config_file():
    """Ensure the config file exists and is valid. Allow repair/edit/reset if invalid."""

    # Generate default config if missing
    if not os.path.exists(config.file_location):
        config.generate_default()
        console.print("[INFO] A default config file has been generated.")

    automatic_repair_failed = False

    while True:
        try:
            config.load()
            is_valid = config.validate()
        except Exception as e:
            console.print(
                f"[ERROR] Config validation raised an exception: {e}", style="#B83B5E"
            )
            is_valid = False

        if is_valid:
            break  # valid -> exit

        if not automatic_repair_failed:
            console.print("[INFO] Attempting automatic config file repair...")
            config.repair()
            automatic_repair_failed = True
            continue  # check the repaired file again

        # In case the automatic repair fails
        console.print()
        selected_action = qy.select(
            message="Choose an action:",
            choices=["Edit config file", "Reset config file"],
            style=DEFAULT_QY_STYLE,
        ).ask()

        if selected_action == "Edit config file":
            let_user_change_config_file(reset_instead_of_discard=True)
        elif selected_action == "Reset config file":
            config.generate_default(overwrite=True)
        else:
            sys.exit(1)


def show_config_operations():
    """Display available config operations and let the user select one interactively."""

    config_operations = [
        qy.Choice(
            title="Edit",
            description="Open the config file in your default text editor.",
            value=let_user_change_config_file,
        ),
        qy.Choice(
            title="Validate",
            description="Validate the syntax of the config file.",
            value=validate_with_feedback,
        ),
        qy.Choice(
            title="Reset",
            description="Reset the config file to its default settings.",
            value=lambda: config.generate_default(overwrite=True),
        ),
        qy.Choice(
            title="Exit",
        ),
    ]

    while True:
        # Prompt user to select an operation
        console.print()
        selected_operation = qy.select(
            message="Config file operation:",
            choices=config_operations,
            use_search_filter=True,
            use_jk_keys=False,
            style=DEFAULT_QY_STYLE,
        ).ask()

        if selected_operation is None or selected_operation == "Exit":
            break

        console.print()
        selected_operation()
        console.print()


def let_user_change_config_file(reset_instead_of_discard: bool = False):
    """
    Open the config file in the user's preferred text editor, validate changes,
    and reload if valid. If invalid, allow the user to discard or retry.

    Args:
        reset_instead_of_discard: Replace the option "Discard changes" with "Reset config file" if True
    """

    # Backup current config
    backup_path = config.file_location.with_suffix(".bak")
    try:
        shutil.copy(config.file_location, backup_path)
    except FileNotFoundError:
        # If no existing config, just create an empty backup
        backup_path.write_text("")
    while True:
        # Open file in editor
        open_in_editor(config_file_location)

        # Validate new config
        try:
            config.load()
            is_valid = config.validate()
        except Exception as e:
            console.print(
                f"[ERROR] Validation raised an exception: {e}", style="#B83B5E"
            )
            is_valid = False

        if is_valid:
            console.print("[INFO] Configuration saved successfully.", style="green")
            break  # exit loop if valid

        # If validation failed
        console.print("[ERROR] Configuration is invalid.", style="#B83B5E")
        console.print()
        selected_action = qy.select(
            message="Choose an action:",
            choices=[
                "Edit again",
                "Reset config file" if reset_instead_of_discard else "Discard changes",
            ],
            style=DEFAULT_QY_STYLE,
        ).ask()

        if selected_action == "Reset config file":
            config.generate_default(overwrite=True)
            return

        if selected_action == "Discard changes":
            # Restore backup
            shutil.copy(backup_path, config.file_location)
            config.load()
            console.print("[INFO] Changes discarded.")
            break
        # else: loop continues for "Edit again"


def open_in_editor(file_path: str | Path):
    """
    Open the given file in the user's preferred text editor and wait until it is closed.

    Respects the environment variable EDITOR if set, otherwise:
      - On Windows: opens with 'notepad'
      - On macOS: uses 'open -W -t'
      - On Linux: tries common editors (nano, vim) or falls back to xdg-open (non-blocking)
    """

    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    editor = os.environ.get("EDITOR")

    # --- Windows ---
    if platform.system() == "Windows":
        if editor:
            subprocess.run([editor, str(path)], check=False)
        else:
            # notepad blocks until file is closed
            subprocess.run(["notepad", str(path)], check=False)
        return

    # --- macOS ---
    if platform.system() == "Darwin":
        if editor:
            subprocess.run([editor, str(path)], check=False)
        else:
            # `open -W` waits until the app is closed
            subprocess.run(["open", "-W", "-t", str(path)], check=False)
        return

    # --- Linux / Unix ---
    if platform.system() == "Linux":
        if editor:
            subprocess.run([editor, str(path)], check=False)
            return
        # try common console editors
        for candidate in ["nano", "vim", "vi"]:
            if shutil.which(candidate):
                subprocess.run([candidate, str(path)], check=False)
                return
        # fallback: GUI open (non-blocking)
        subprocess.Popen(["xdg-open", str(path)])
        console.print(
            "[INFO] File opened in default GUI editor. Please close it manually."
        )
        input("[INFO] Press Enter here when you're done editing...")


def validate_with_feedback():
    config.load()
    result = config.validate()
    if result is True:
        console.print("[INFO] Configuration is valid.", style="green")
    else:
        console.print("[ERROR] Configuration is invalid.", style="#B83B5E")
    return result


def reset_with_feedback():
    result = config.generate_default(overwrite=True)
    if result is True:
        console.print("[INFO] Configuration successfully reset.", style="green")
    else:
        console.print("[ERROR] Configuration reset failed.", style="#B83B5E")
    return result


# --- Config file defintions ---
config_file_location = os.path.join(SCRIPT_HOME_DIR, "config.yml")
config_schema = {
    "update_config": {
        "comment": "Settings for controlling the update check",
        "check_for_updates_at_launch": {
            "type": bool,
            "default": True,
            "validator": bool_validator,
            "comment": "If true, the application checks for available updates at launch once the cache lifetime is over",
        },
        "consider_beta_versions_as_available_updates": {
            "type": bool,
            "default": False,
            "validator": bool_validator,
            "comment": "If true, beta releases will be considered as available updates",
        },
        "check_for_updates_cache_lifetime_seconds": {
            "type": int,
            "default": 86400,
            "min": 0,
            "max": 604800,
            "validator": int_range_validator,
            "comment": "Amount of time which needs to pass before trying to fetch for updates again",
        },
    },
    "ca_server_config": {
        "comment": "Settings that affect the CA server behavior",
        "default_ca_server": {
            "type": str,
            "default": "",
            "validator": server_validator,
            "comment": "The CA server which will be used by default (optionally with :port)",
        },
        "trust_unknow_certificates_by_default": {
            "type": bool,
            "default": False,
            "validator": bool_validator,
            "comment": "If true, any CA server providing an unknown self-signed certificate will be trusted by default",
        },
        "fetch_root_ca_certificate_automatically": {
            "type": bool,
            "default": True,
            "validator": bool_validator,
            "comment": "If false, the root certificate won't be fetched automatically from the CA server. You will need to enter the fingerprint manually when installing a root CA certificate",
        },
    },
}

# This object will be used to manipulate the config file
config = Configuration(config_file_location, schema=config_schema)

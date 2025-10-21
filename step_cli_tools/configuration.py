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
        Manage persistent user settings in a YAML file with typed schema and comment support.
        Note, that the load() method MUST be called manually once.

        Args:
            file_location: Absoulte path to the config file
            schema: Settings schema defining 'type', 'default', and optional 'validator' and 'comment'.
            autosave: If True, automatically save after each set() call.
        """
        self.file_location = Path(file_location)
        self.file_location.parent.mkdir(parents=True, exist_ok=True)
        self.schema = schema
        self.autosave = autosave
        self._data = CommentedMap()

    # --- File and public API handling ---
    def load(self):
        """Load YAML and merge defaults, building CommentedMap with comments."""
        if self.file_location.exists():
            try:
                loaded = yaml.load(self.file_location.read_text()) or {}
            except Exception as e:
                console.print(f"[WARNING] Failed to load config: {e}", style="yellow")
                loaded = {}
        else:
            loaded = {}

        self._data = self._build_commented_data(self.schema, loaded)

    def save(self):
        """Save current configuration to YAML file."""
        try:
            with self.file_location.open("w", encoding="utf-8") as f:
                yaml.dump(self._data, f)
        except (OSError, IOError) as e:
            console.print(
                f"[ERROR] Could not save settings to {self.file_location}: {e}",
                style="red",
            )

    def reset(self) -> bool:
        """
        Reset the configuration file to default values.

        Steps:
          1. If a configuration file exists, create a timestamped backup in the same directory.
          2. Rebuild a fresh configuration from schema defaults.
          3. Save and reload the new configuration.

        Returns:
            bool: True if reset succeeded, False otherwise.
        """
        try:
            if self.file_location.exists():
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                backup_path = self.file_location.with_name(
                    f"{self.file_location.stem}_backup_{timestamp}{self.file_location.suffix}"
                )
                shutil.copy2(self.file_location, backup_path)
                console.print(f"[INFO] Created backup: {backup_path}")

            # Rebuild fresh data structure from schema defaults
            self._data = self._build_commented_data(self.schema)

            # Save new clean config
            self.save()
            self.load()

            console.print(
                f"[INFO] Configuration reset successfully: {self.file_location}",
                style="green",
            )
            return True

        except Exception as e:
            console.print(f"[ERROR] Failed to reset configuration: {e}", style="red")
            return False

    def get(self, key: str):
        """Retrieve a setting value using a dotted key path, falls back to default."""
        parts = key.split(".")
        data = self._data
        for part in parts:
            if not isinstance(data, dict) or part not in data:
                return self._nested_get_default(parts)
            data = data[part]
        return data

    def set(self, key: str, value):
        """Set a setting value using a dotted key path, cast to schema type if needed."""
        parts = key.split(".")
        data = self._data

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
                    style="yellow",
                )

        data[parts[-1]] = value
        if self.autosave:
            self.save()

    def validate(self, key: str | None = None) -> bool:
        """
        Validate settings against their schema validators.

        If a key is provided, only that single setting (using dotted notation)
        will be validated. If no key is given, the entire configuration is checked
        recursively against all validators defined in the schema.

        The validator for each key is taken from the schema entry under "validator".
        Validators can either:
          • Return None → value is valid
          • Return a string → value is invalid (string describes the error)
          • Raise an Exception → considered invalid

        Args:
            key: Optional dotted key path (e.g. "update_settings.retry_count")
                 to validate only that specific entry.

        Returns:
            bool: True if all checked values are valid, False otherwise.
        """
        if key:
            parts = key.split(".")
            meta = self._nested_get_meta(parts)
            if not meta:
                console.print(f"[WARNING] No schema entry for '{key}'", style="yellow")
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
                        style="yellow",
                    )
                    return False

                result = validator(value)

            except Exception as e:
                console.print(
                    f"[ERROR] Validator for '{key}' raised an exception: {e}",
                    style="red",
                )
                return False

            if result is None:
                return True
            if isinstance(result, str):
                console.print(
                    f"[WARNING] Validation failed for '{key}': {result}", style="yellow"
                )
                return False

            console.print(
                f"[ERROR] Validator for '{key}' returned unsupported value: {result!r}",
                style="red",
            )
            return False

        # No specific key → validate full schema recursively
        return self._validate_recursive(self._data, self.schema, prefix="")

    # --- Internal helpers ---
    def _wrap_validator(self, meta, validator):
        """
        Wrap known validators with parameters from schema if needed.

        Args:
            meta: The schema metadata dict for the key.
            validator: The original validator function.

        Returns:
            A callable validator, possibly wrapped with schema params.
        """
        if callable(validator):
            if validator is int_range_validator and "min" in meta and "max" in meta:
                return int_range_validator(meta["min"], meta["max"])
            elif validator is str_allowed_validator and "allowed" in meta:
                return str_allowed_validator(meta["allowed"])
        return validator

    def _validate_recursive(self, data: dict, schema: dict, prefix: str) -> bool:
        """
        Recursively validate all settings against their schema definitions.

        This method walks through the nested schema structure, retrieves each value
        from the corresponding data dictionary, and applies the configured validator
        if one exists.

        Rules:
          • If an entry has no "type", it is treated as a nested schema.
          • If a validator is defined, it must be callable.
          • A validator should return:
              - None → valid
              - str  → invalid (string contains error message)
              - raise Exception → invalid

        Args:
            data: The current level of the settings data being validated.
            schema: The schema dict defining expected structure and validators.
            prefix: Dotted prefix path used for nested key names.

        Returns:
            bool: True if all values at this level (and below) are valid, False otherwise.
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
                        style="yellow",
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
                            style="yellow",
                        )
                        ok = False
                        continue

                    result = validator(value)
                    if isinstance(result, str):
                        console.print(
                            f"[WARNING] Validation failed for '{full_key}': {result}",
                            style="yellow",
                        )
                        ok = False
                    elif result is not None:
                        console.print(
                            f"[ERROR] Validator for '{full_key}' returned unsupported type: {result!r}",
                            style="red",
                        )
                        ok = False

                except Exception as e:
                    console.print(
                        f"[ERROR] Validator for '{full_key}' raised: {e}", style="red"
                    )
                    ok = False

        return ok

    def _nested_get_meta(self, keys: list[str]) -> dict | None:
        data = self.schema
        for k in keys:
            if not isinstance(data, dict) or k not in data:
                return None
            data = data[k]
        return data if isinstance(data, dict) else None

    def _nested_get_default(self, keys: list[str]):
        data = self.schema
        for k in keys:
            if not isinstance(data, dict) or k not in data:
                console.print(
                    f"[WARNING] Missing default for key '{'.'.join(keys)}'",
                    style="yellow",
                )
                return None
            data = data[k]
            if isinstance(data, dict) and "default" in data:
                return data["default"]
        return None

    def _nested_get_type(self, keys: list[str]):
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
    ) -> CommentedMap:
        data = data or {}
        node = CommentedMap()

        for i, (key, meta) in enumerate(schema.items()):
            if isinstance(key, str) and key.startswith("_"):
                continue
            if not isinstance(meta, dict):
                continue

            if "type" not in meta:
                child_node = self._build_commented_data(
                    meta, data.get(key, {}), indent + 2, top_level=False
                )
                node[key] = child_node
            else:
                node[key] = data.get(key, meta.get("default"))

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


def check_and_repair_config_file() -> None:
    """
    Ensure the config file exists and is valid.
    If invalid, allow the user to edit or reset.
    """
    # Generate default if missing
    if not os.path.exists(config_file_location):
        config.load()
        config.save()
        console.print("[INFO] A default config file has been generated.")

    # Validation / repair loop
    while True:
        try:
            config.load()
            is_valid = config.validate()
        except Exception as e:
            console.print(
                f"[ERROR] Config validation raised an exception: {e}", style="red"
            )
            is_valid = False

        if is_valid:
            break

        choice = qy.select(
            "Choose an action:",
            choices=["Edit config file", "Reset config file"],
            style=DEFAULT_QY_STYLE,
        ).ask()

        if choice == "Edit config file":
            let_user_change_config_file(True)
        elif choice == "Reset config file":
            config.reset()
        else:
            sys.exit(1)


def show_config_operations() -> None:
    """Display available config operations and let the user select one interactively."""
    config_operation_switch = {
        "Open": let_user_change_config_file,
        "Validate": validate_with_feedback,
        "Reset": config.reset,
        "Exit": lambda: None,  # no-op for exit
    }
    options = list(config_operation_switch.keys())

    while True:
        # Prompt user to select an operation
        operation = qy.select(
            "Config file options:",
            style=DEFAULT_QY_STYLE,
            choices=options,
            use_search_filter=True,
            use_jk_keys=False,
        ).ask()

        if operation == "Exit" or operation is None:
            break

        action = config_operation_switch.get(
            operation,
            lambda: console.print(
                f"[WARNING] Unknown operation: {operation}", style="yellow"
            ),
        )

        console.print()
        action()
        console.print()


def let_user_change_config_file(reset_instead_of_discard: bool = False) -> None:
    """
    Open the config file in the user's preferred text editor, validate changes,
    and reload if valid. If invalid, allow the user to discard or retry.
    """
    while True:
        # Backup current config
        backup_path = config.file_location.with_suffix(".bak")
        try:
            shutil.copy(config.file_location, backup_path)
        except FileNotFoundError:
            # If no existing config, just create an empty backup
            backup_path.write_text("")

        # Open file in editor
        open_in_editor(config_file_location)

        # Validate new config
        try:
            config.load()
            is_valid = config.validate()
        except Exception as e:
            console.print(f"[ERROR] Validation raised an exception: {e}", style="red")
            is_valid = False

        if is_valid:
            console.print("[INFO] Configuration updated successfully.", style="green")
            break  # exit loop if valid

        # If validation failed
        console.print("[ERROR] Configuration is invalid.", style="red")
        choice = qy.select(
            "Choose an action:",
            choices=[
                "Edit again",
                "Reset config file" if reset_instead_of_discard else "Discard changes",
            ],
            style=DEFAULT_QY_STYLE,
        ).ask()

        if choice == "Reset config file":
            config.reset()
            return

        if choice == "Discard changes":
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
        console.print("[ERROR] Configuration is invalid.", style="red")
    return result


def reset_with_feedback():
    result = config.reset()
    if result is True:
        console.print("[INFO] Configuration successfully reset.", style="green")
    else:
        console.print("[ERROR] Configuration reset failed.", style="red")
    return result


# --- Config file defintions ---
config_file_location = os.path.join(SCRIPT_HOME_DIR, "config.yml")
config_schema = {
    "update_config": {
        "comment": "Settings controlling the search for newer versions",
        "check_for_updates_at_launch": {
            "type": bool,
            "default": True,
            "validator": bool_validator,
            "comment": "If enabled, the application checks for available updates at launch once the cache lifetime is over",
        },
        "consider_beta_versions_as_available_updates": {
            "type": bool,
            "default": False,
            "validator": bool_validator,
            "comment": "If enabled, beta releases will be considered as available updates",
        },
        "check_for_updates_cache_lifetime_seconds": {
            "type": int,
            "default": 86400,
            "min": 0,
            "max": 604800,
            "validator": int_range_validator,
            "comment": "Amount of time which needs to pass before trying to fetch for updates",
        },
    },
    "ca_server_config": {
        "comment": "Settings that affect the default ca server",
        "default_ca_server": {
            "type": str,
            "default": "",
            "validator": server_validator,
            "comment": "The ca server which will be used by default (optionally with :port)",
        },
        "trust_unknow_ca_servers_by_default": {
            "type": bool,
            "default": False,
            "validator": bool_validator,
            "comment": "If enabled, any ca server providing an unknown self signed certificate will be trusted by default. (NO_EFFECT_YET)",
        },
    },
}

# This object will be used to manipulate the config file
config = Configuration(config_file_location, schema=config_schema)
check_and_repair_config_file()
config.load()

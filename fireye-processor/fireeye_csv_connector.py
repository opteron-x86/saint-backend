import os
import json
import csv
import gzip
from tqdm import tqdm
from dimensional.modules.inputs.generic_localmulti_connector import LocalMultiFileInputConnector

class FireEyeCSVInputConnector(LocalMultiFileInputConnector):
    def __init__(
            self, 
            debug_mode: bool, 
            cache_path: str, 
            cache_sec: int, 
            folder_path: str,
            file_extensions: str,
            **kwargs
            ):
        
        if debug_mode:
            for key, value in kwargs.items():
                print(f"Unhandled kwargs: {key} -> {type(value).__name__}: {value}")

        # Extract the specific kwargs before calling super()
        self.cache_path = str(cache_path)
        self.cache_sec = int(cache_sec)
        self.folder_path = str(folder_path)
        self.file_extensions = set(self.parse_file_extensions(file_extensions))

        super().__init__(
            debug_mode, 
            cache_path, 
            cache_sec, 
            folder_path,
            file_extensions,
            **kwargs
            )
 
        os.makedirs(self.cache_path, exist_ok=True)
        if not os.path.exists(self.folder_path) or not os.path.isdir(self.folder_path):
            raise FileNotFoundError(f"The folder {self.folder_path} does not exist or is not a directory.")

    def get_staged_data(self, file_name, max_age_seconds):
        if self._is_data_fresh(file_name, max_age_seconds):
            file_path = os.path.join(self.cache_path, file_name)
            if file_path.endswith('.gz'):
                try:
                    with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                        return f.read(), None
                except Exception as e:
                    print(f"❌ Failed to read GZ cache: {file_path}: {e}")
                    return None, None
            else:
                return self._process_single_file(file_path), None
        return None, None

    def parse_file_extensions(self, file_extensions_str):
        extensions = file_extensions_str.split(',')
        return ['.' + ext if not ext.startswith('.') else ext for ext in extensions]
 
    def fetch_data(self):
        file_name = self._get_output_filename()
        is_fresh, remaining_seconds = self._is_data_fresh(file_name, self.cache_sec)
        if is_fresh:
            print(f"Using fresh data from cache: {file_name} (expires in {remaining_seconds} seconds)")
            data, _ = self.get_staged_data(file_name, self.cache_sec)
            return data
        else:
            return self._fetch_and_process_data()
 
    def _fetch_and_process_data(self):
        all_rows = []
        target_files = self._get_all_files_recursively(self.folder_path)
    
        for file_path in tqdm(target_files, desc="Processing CSV Files", unit=" files"):
            rows = self._read_csv(file_path)
            if rows:
                all_rows.extend(rows)
    
        gzipped_filename = self._get_output_filename()
        self._save_gzipped(json.dumps(all_rows, indent=2), gzipped_filename)
        return json.dumps(all_rows)
 
    def _get_all_files_recursively(self, folder_path):
        all_files = []
        for root, _, files in os.walk(folder_path):
            for file in files:
                if any(file.endswith(ext) for ext in self.file_extensions):
                    all_files.append(os.path.join(root, file))
        return all_files
 
    def _process_single_file(self, file_path):
        return self._read_csv(file_path)
  
    def _read_csv(self, file_path, delimiter=','):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                sample = file.readline()
                if '\t' in sample:
                    raise ValueError(f"❌ Detected tab-delimited file instead of CSV: {file_path}")
                file.seek(0)  # Reset file pointer
    
                reader = csv.DictReader(file, delimiter=delimiter)
                rows = [row for row in reader if any(cell.strip() for cell in row.values() if cell)]
                return rows
        except Exception as e:
            print(f"❌ Failed to read {file_path}: {e}")
            return []

    def _get_output_filename(self):
        ext = "json.gz"
        return f"local_multi_{os.path.basename(self.folder_path)}.{ext}"
 
    def _save_gzipped(self, data, file_name):
        file_path = os.path.join(self.cache_path, file_name)
        with gzip.open(file_path, 'wt', encoding='utf-8') as file:
            file.write(data)
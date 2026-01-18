"""Service for managing catalog files."""
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class CatalogService:
    """Handles catalog file operations."""
    
    def __init__(self, catalog_path: Path, create_backups: bool = True):
        """Initialize catalog service.
        
        Args:
            catalog_path: Path to catalog directory
            create_backups: Whether to create backups before saving
        """
        self.catalog_path = catalog_path
        self.create_backups = create_backups
    
    def resolve_path(self, relative_catalog_file: str) -> Path:
        """Resolve catalog file path.
        
        Args:
            relative_catalog_file: Relative path to catalog file (e.g., 'catalog.json')
            
        Returns:
            Absolute path to catalog file
        """
        # Resolve relative to catalog_path
        full_path = (self.catalog_path / relative_catalog_file).resolve()
        
        return full_path
    
    def load_catalog(self, catalog_path: str) -> Tuple[List[Dict], Path]:
        """Load a catalog file.
        
        Args:
            catalog_path: Relative path to catalog file
            
        Returns:
            Tuple of (catalog data, absolute file path)
            
        Raises:
            FileNotFoundError: If catalog file doesn't exist
            json.JSONDecodeError: If catalog file is invalid JSON
        """
        full_path = self.resolve_path(catalog_path)
        
        with open(full_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return data, full_path
    
    def save_catalog(self, catalog_path: str, data: List[Dict]) -> bool:
        """Save catalog file with optional backup.
        
        Args:
            catalog_path: Relative path to catalog file
            data: Catalog data to save
            
        Returns:
            True if saved successfully
            
        Raises:
            ValueError: If data is invalid
        """
        full_path = self.resolve_path(catalog_path)
        
        # Validate that data is a list
        if not isinstance(data, list):
            raise ValueError("Catalog data must be a list")
        
        # Create backup if enabled and file exists
        if self.create_backups and full_path.exists():
            backup_path = full_path.with_suffix(full_path.suffix + '.bak')
            shutil.copy2(full_path, backup_path)
        
        # Save catalog
        with open(full_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return True
    
    def list_catalogs_recursive(self, catalog_path: str) -> List[Dict]:
        """Load catalog and all referenced catalogs recursively.
        
        Args:
            catalog_path: Relative path to main catalog file
            
        Returns:
            List of all catalog entries with metadata
        """
        result = []
        visited = set()
        
        def _load_recursive(path: str, parent: Optional[str] = None):
            """Recursively load catalogs."""
            if path in visited:
                return
            visited.add(path)
            
            try:
                data, full_path = self.load_catalog(path)
                
                # Validate that data is a list
                if not isinstance(data, list):
                    print(f"Warning: {path} does not contain a list (found {type(data).__name__})")
                    return
                
                for item in data:
                    # Validate that item is a dictionary
                    if not isinstance(item, dict):
                        print(f"Warning: Item in {path} is not a dictionary (found {type(item).__name__}): {item}")
                        continue
                    
                    # Add metadata
                    item_with_meta = {
                        **item,
                        '_source_file': path,
                        '_parent': parent,
                        '_file_path': str(full_path)
                    }
                    result.append(item_with_meta)
                    
                    # If item references another catalog file, load it
                    if 'file' in item and 'catalog' in item:
                        # Resolve relative to current catalog's directory
                        current_dir = Path(path).parent
                        referenced_file = str(current_dir / item['file'])
                        _load_recursive(referenced_file, path)
            
            except (FileNotFoundError, json.JSONDecodeError) as e:
                # Log error but continue
                print(f"Warning: Could not load {path}: {e}")
        
        _load_recursive(catalog_path)
        return result
    
    def get_catalog_stats(self, catalog_path: str) -> Dict:
        """Get statistics about a catalog.
        
        Args:
            catalog_path: Relative path to catalog file
            
        Returns:
            Dictionary with statistics
        """
        catalogs = self.list_catalogs_recursive(catalog_path)
        
        # Count by type
        type_counts = {}
        for item in catalogs:
            item_type = item.get('type', 'unknown')
            type_counts[item_type] = type_counts.get(item_type, 0) + 1
        
        # Count by owner
        owner_counts = {}
        for item in catalogs:
            owner = item.get('owner', 'unknown')
            owner_counts[owner] = owner_counts.get(owner, 0) + 1
        
        return {
            'total_services': len(catalogs),
            'by_type': type_counts,
            'by_owner': owner_counts,
            'unique_files': len(set(item['_source_file'] for item in catalogs))
        }
    
    def search_catalogs(self, catalog_path: str, query: str) -> List[Dict]:
        """Search catalogs by name, url, or comment.
        
        Args:
            catalog_path: Relative path to catalog file
            query: Search query string
            
        Returns:
            List of matching catalog entries
        """
        catalogs = self.list_catalogs_recursive(catalog_path)
        query_lower = query.lower()
        
        results = []
        for item in catalogs:
            # Search in name, url, comment
            searchable = ' '.join([
                str(item.get('name', '')),
                str(item.get('url', '')),
                str(item.get('comment', '')),
                str(item.get('catalog', ''))
            ]).lower()
            
            if query_lower in searchable:
                results.append(item)
        
        return results
    
    def validate_json(self, json_string: str) -> Tuple[bool, Optional[str], Optional[List]]:
        """Validate JSON string.
        
        Args:
            json_string: JSON string to validate
            
        Returns:
            Tuple of (is_valid, error_message, parsed_data)
        """
        try:
            data = json.loads(json_string)
            
            # Additional validation: must be a list
            if not isinstance(data, list):
                return False, "Catalog must be a JSON array", None
            
            return True, None, data
        
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}", None
    
    def is_master_catalog(self, item: Dict) -> bool:
        """Check if an item is a master catalog (has 'file' parameter).
        
        Args:
            item: Catalog item to check
            
        Returns:
            True if item is a master catalog, False otherwise
        """
        return 'file' in item and 'catalog' in item
    
    def build_catalog_tree(self, root_catalog: str = 'catalog.json') -> Dict:
        """Build hierarchical tree structure from catalogs.
        
        Args:
            root_catalog: Root catalog file to start from
            
        Returns:
            Tree structure with master catalogs and service entries
        """
        def _build_node(catalog_path: str, parent_name: str = None) -> Dict:
            """Recursively build tree node."""
            try:
                data, full_path = self.load_catalog(catalog_path)
                
                if not isinstance(data, list):
                    return None
                
                node = {
                    'path': catalog_path,
                    'full_path': str(full_path),
                    'name': parent_name or catalog_path,
                    'children': [],
                    'services': []
                }
                
                for idx, item in enumerate(data):
                    if not isinstance(item, dict):
                        continue
                    
                    if self.is_master_catalog(item):
                        # This is a master catalog - add as child node
                        current_dir = Path(catalog_path).parent
                        child_path = str(current_dir / item['file'])
                        child_node = _build_node(child_path, item.get('catalog', item['file']))
                        if child_node:
                            node['children'].append(child_node)
                    else:
                        # This is a service entry - add to services list
                        item_with_meta = {
                            **item,
                            '_index': idx,
                            '_file': catalog_path
                        }
                        node['services'].append(item_with_meta)
                
                return node
            
            except Exception as e:
                print(f"Warning: Could not build tree for {catalog_path}: {e}")
                return None
        
        return _build_node(root_catalog)
    
    def get_service_entry(self, catalog_path: str, entry_index: int) -> Optional[Dict]:
        """Get a specific service entry from a catalog file.
        
        Args:
            catalog_path: Relative path to catalog file
            entry_index: Index of the entry in the catalog
            
        Returns:
            Service entry dictionary or None if not found
        """
        try:
            data, _ = self.load_catalog(catalog_path)
            
            if not isinstance(data, list) or entry_index >= len(data):
                return None
            
            entry = data[entry_index]
            
            # Don't return master catalogs
            if self.is_master_catalog(entry):
                return None
            
            return entry
        
        except Exception as e:
            print(f"Error getting service entry: {e}")
            return None
    
    def update_service_entry(self, catalog_path: str, entry_index: int, updated_entry: Dict) -> bool:
        """Update a specific service entry in a catalog file.
        
        Args:
            catalog_path: Relative path to catalog file
            entry_index: Index of the entry to update
            updated_entry: Updated entry data
            
        Returns:
            True if updated successfully, False otherwise
        """
        try:
            data, full_path = self.load_catalog(catalog_path)
            
            if not isinstance(data, list) or entry_index >= len(data):
                return False
            
            # Don't allow updating master catalogs
            if self.is_master_catalog(data[entry_index]):
                return False
            
            # Update the entry
            data[entry_index] = updated_entry
            
            # Save the catalog
            return self.save_catalog(catalog_path, data)
        
        except Exception as e:
            print(f"Error updating service entry: {e}")
            return False

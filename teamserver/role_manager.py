import os
import json
import uuid
from core.models import NeoC2DB

class RoleManager:
    def __init__(self, db):
        self.db = db

    def create_role(self, name, description, permissions):
        existing_role = self.db.execute(
            "SELECT id FROM roles WHERE name = ?",
            (name,)
        ).fetchone()
        if existing_role:
            return {
                "success": False,
                "message": "Role already exists"
            }
        
        role_id = str(uuid.uuid4())
        created_at = str(uuid.uuid4())  # Convert UUID to string
        self.db.execute(
            "INSERT INTO roles (id, name, description, permissions, created_at) VALUES (?, ?, ?, ?, ?)",
            (role_id, name, description, json.dumps(permissions), created_at)
        )
        return {
            "success": True,
            "role_id": role_id,
            "message": "Role created successfully"
        }

    def get_role(self, role_id):
        role_data = self.db.execute(
            "SELECT id, name, description, permissions FROM roles WHERE id = ?",
            (role_id,)
        ).fetchone()
        if not role_data:
            return None
        return {
            "id": role_data['id'],
            "name": role_data['name'],
            "description": role_data['description'],
            "permissions": json.loads(role_data['permissions'])
        }

    def get_role_by_name(self, name):
        role_data = self.db.execute(
            "SELECT id, name, description, permissions FROM roles WHERE name = ?",
            (name,)
        ).fetchone()
        if not role_data:
            return None
        return {
            "id": role_data['id'],
            "name": role_data['name'],
            "description": role_data['description'],
            "permissions": json.loads(role_data['permissions'])
        }

    def update_role(self, role_id, updates):
        set_clauses = []
        params = []
        if 'name' in updates:
            set_clauses.append("name = ?")
            params.append(updates['name'])
        if 'description' in updates:
            set_clauses.append("description = ?")
            params.append(updates['description'])
        if 'permissions' in updates:
            set_clauses.append("permissions = ?")
            params.append(json.dumps(updates['permissions']))
        
        if not set_clauses:
            return {
                "success": False,
                "message": "No updates provided"
            }
        
        # Add role_id to params
        params.append(role_id)
        
        self.db.execute(
            f"UPDATE roles SET {', '.join(set_clauses)} WHERE id = ?",
            tuple(params)
        )
        return {
            "success": True,
            "message": "Role updated successfully"
        }

    def list_roles(self):
        roles_data = self.db.execute("SELECT id, name, description FROM roles").fetchall()
        roles = []
        for role_data in roles_data:
            roles.append({
                "id": role_data['id'],
                "name": role_data['name'],
                "description": role_data['description']
            })
        return roles

import os
import sys
import json
import time
import threading
import socket
import ssl
import logging
from datetime import datetime
import uuid
from core.config import NeoC2Config
from core.models import NeoC2DB
from teamserver.session_manager import SessionManager
from teamserver.user_manager import UserManager
from teamserver.role_manager import RoleManager
from teamserver.audit_logger import AuditLogger
from teamserver.listener_manager import ListenerManager  # Added for Phase 3

class TeamServer:
    def __init__(self, config_path=None):
        self.config = NeoC2Config(config_path)
        self.db = NeoC2DB(self.config.get("database.path"))
        
        self.session_manager = SessionManager(self.db)
        self.user_manager = UserManager(self.db)
        self.role_manager = RoleManager(self.db)
        self.audit_logger = AuditLogger(self.db)
        self.listener_manager = ListenerManager(self.config, self.db)  # Added for Phase 3
        
        self.host = self.config.get("teamserver.host", "0.0.0.0")
        self.port = self.config.get("teamserver.port", 5000)
        self.ssl_enabled = self.config.get("teamserver.ssl_enabled", True)
        self.ssl_cert = self.config.get("teamserver.ssl_cert", "teamserver.crt")
        self.ssl_key = self.config.get("teamserver.ssl_key", "teamserver.key")
        
        # Logging
        self.setup_logging()
        
        self.running = False
        self.start_time = None
        self.server_socket = None
        
        self.active_sessions = {}
        
        self.event_handlers = {
            "agent_checkin": self.handle_agent_checkin,
            "task_result": self.handle_task_result,
            "user_login": self.handle_user_login,
            "user_logout": self.handle_user_logout,
            "task_created": self.handle_task_created,
            "module_executed": self.handle_module_executed
        }
    
    def setup_logging(self):
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(log_dir, "teamserver.log")),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger("TeamServer")
    
    def start(self):
        try:
            self.logger.info("Starting NeoC2 Team Server...")
            self.start_time = datetime.now()
            self.running = True
            
            self.initialize_database()
            
            default_listener_id = self.listener_manager.create_http_listener(
                name='default',
                host='0.0.0.0',
                port=443,
                profile_name='default',
                use_https=True
            )
            self.listener_manager.start_listener(default_listener_id)
            
            web_thread = threading.Thread(target=self.start_web_interface)
            web_thread.daemon = True
            web_thread.start()
            
            self.start_team_server_socket()
            
            self.logger.info(f"Team server started on {self.host}:{self.port}")
            
            self.server_loop()
            
        except Exception as e:
            self.logger.error(f"Error starting team server: {str(e)}")
        finally:
            self.stop()
    
    def stop(self):
        self.logger.info("Stopping NeoC2 Team Server...")
        self.running = False
        
        if self.server_socket:
            self.server_socket.close()
        
        for session_id, session in self.active_sessions.items():
            session.close()
        
        for listener_id in self.listener_manager.listeners:
            self.listener_manager.stop_listener(listener_id)
        
        self.logger.info("Team server stopped")
    
    def initialize_database(self):
        self.db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (role_id) REFERENCES roles(id)
        )
        ''')
        
        self.db.execute('''
        CREATE TABLE IF NOT EXISTS roles (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            permissions TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        self.db.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            last_activity TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
        
        self.db.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
        
        default_roles = [
            {
                "id": "admin",
                "name": "Administrator",
                "description": "Full access to all features",
                "permissions": json.dumps(["*"])
            },
            {
                "id": "operator",
                "name": "Operator",
                "description": "Can manage agents and execute modules",
                "permissions": json.dumps([
                    "agents.list",
                    "agents.interact",
                    "tasks.create",
                    "tasks.execute",
                    "modules.list",
                    "modules.execute",
                    "results.view"
                ])
            },
            {
                "id": "viewer",
                "name": "Viewer",
                "description": "Read-only access",
                "permissions": json.dumps([
                    "agents.list",
                    "tasks.list",
                    "modules.list",
                    "results.view"
                ])
            }
        ]
        
        for role in default_roles:
            self.db.execute(
                "INSERT OR IGNORE INTO roles (id, name, description, permissions) VALUES (?, ?, ?, ?)",
                (role["id"], role["name"], role["description"], role["permissions"])
            )
        
        admin_exists = self.db.execute(
            "SELECT id FROM users WHERE username = ?", ("admin",)
        ).fetchone()
        
        if not admin_exists:
            from werkzeug.security import generate_password_hash
            password_hash = generate_password_hash("password")
            self.db.execute(
                "INSERT INTO users (id, username, password_hash, role_id) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), "admin", password_hash, "admin")
            )
    
    def start_web_interface(self):
        from web.web_app import NeoC2Web  # Moved here to avoid circular import
        self.web_app = NeoC2Web(self.config, self.db, None, None, None)
        self.web_app.start()
    
    def start_team_server_socket(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.logger.info(f"Team server socket listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client_connection,
                        args=(client_socket, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting client connection: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error starting team server socket: {str(e)}")
    
    def handle_client_connection(self, client_socket, addr):
        try:
            self.logger.info(f"New client connection from {addr}")
            
            session = self.authenticate_client(client_socket, addr)
            if not session:
                client_socket.close()
                return
            
            self.active_sessions[session.id] = session
            
            self.handle_client_requests(client_socket, session)
            
        except Exception as e:
            self.logger.error(f"Error handling client connection from {addr}: {str(e)}")
        finally:
            if session and session.id in self.active_sessions:
                del self.active_sessions[session.id]
            
            # Close 
            client_socket.close()
    
    def authenticate_client(self, client_socket, addr):
        try:
            auth_data = client_socket.recv(4096).decode('utf-8')
            auth_request = json.loads(auth_data)
            
            username = auth_request.get('username')
            password = auth_request.get('password')
            
            user = self.user_manager.authenticate(username, password)
            if not user:
                self.logger.warning(f"Authentication failed for user {username} from {addr}")
                return None
            
            session = self.session_manager.create_session(
                user['id'],
                addr[0],
                auth_request.get('user_agent', '')
            )
            
            self.audit_logger.log_event(
                user['id'],
                "user_login",
                "session",
                session.id,
                json.dumps({"ip_address": addr[0]}),
                addr[0]
            )
            
            response = {
                "status": "success",
                "session_id": session.id,
                "user": {
                    "id": user['id'],
                    "username": user['username'],
                    "role": user['role_id']
                }
            }
            
            client_socket.send(json.dumps(response).encode('utf-8'))
            
            return session
            
        except Exception as e:
            self.logger.error(f"Error authenticating client from {addr}: {str(e)}")
            return None
    
    def handle_client_requests(self, client_socket, session):
        try:
            while self.running:
                request_data = client_socket.recv(4096).decode('utf-8')
                if not request_data:
                    break
                
                request = json.loads(request_data)
                
                self.session_manager.update_activity(session.id)
                
                response = self.handle_request(request, session)
                
                client_socket.send(json.dumps(response).encode('utf-8'))
                
        except Exception as e:
            self.logger.error(f"Error handling client request: {str(e)}")
    
    def handle_request(self, request, session):
        """Handle a request from a client"""
        try:
            action = request.get('action')
            
            if not self.role_manager.has_permission(session.user['role_id'], action):
                return {
                    "status": "error",
                    "message": "Permission denied"
                }
            
            if action == "get_agents":
                return self.handle_get_agents(request, session)
            elif action == "interact_agent":
                return self.handle_interact_agent(request, session)
            elif action == "create_task":
                return self.handle_create_task(request, session)
            elif action == "get_tasks":
                return self.handle_get_tasks(request, session)
            elif action == "get_results":
                return self.handle_get_results(request, session)
            elif action == "execute_module":
                return self.handle_execute_module(request, session)
            elif action == "get_sessions":
                return self.handle_get_sessions(request, session)
            elif action == "get_audit_log":
                return self.handle_get_audit_log(request, session)
            elif action == "create_listener":
                return self.handle_create_listener(request, session)
            elif action == "start_listener":
                return self.handle_start_listener(request, session)
            elif action == "stop_listener":
                return self.handle_stop_listener(request, session)
            elif action == "list_listeners":
                return self.handle_list_listeners(request, session)
            else:
                return {
                    "status": "error",
                    "message": f"Unknown action: {action}"
                }
                
        except Exception as e:
            self.logger.error(f"Error handling request: {str(e)}")
            return {
                "status": "error",
                "message": f"Error handling request: {str(e)}"
            }
    
    def handle_get_agents(self, request, session):
        agents = self.db.get_all_agents()
        
        self.audit_logger.log_event(
            session.user['id'],
            "agents.list",
            "agents",
            None,
            None,
            session.ip_address
        )
        
        return {
            "status": "success",
            "agents": agents
        }
    
    def handle_interact_agent(self, request, session):
        agent_id = request.get('agent_id')
        
        agent = self.db.get_agent(agent_id)
        if not agent:
            return {
                "status": "error",
                "message": f"Agent {agent_id} not found"
            }
        
        self.audit_logger.log_event(
            session.user['id'],
            "agents.interact",
            "agent",
            agent_id,
            None,
            session.ip_address
        )
        
        return {
            "status": "success",
            "agent": agent
        }
    
    def handle_create_task(self, request, session):
        agent_id = request.get('agent_id')
        command = request.get('command')
        
        task_id = self.db.add_task(agent_id, command)
        
        self.audit_logger.log_event(
            session.user['id'],
            "tasks.create",
            "task",
            task_id,
            json.dumps({"agent_id": agent_id, "command": command}),
            session.ip_address
        )
        
        # Trigger event
        self.trigger_event("task_created", {
            "task_id": task_id,
            "agent_id": agent_id,
            "command": command,
            "user_id": session.user['id']
        })
        
        return {
            "status": "success",
            "task_id": task_id
        }
    
    def handle_get_tasks(self, request, session):
        agent_id = request.get('agent_id')
        
        tasks = self.db.get_agent_tasks(agent_id)
        
        self.audit_logger.log_event(
            session.user['id'],
            "tasks.list",
            "tasks",
            None,
            json.dumps({"agent_id": agent_id}),
            session.ip_address
        )
        
        return {
            "status": "success",
            "tasks": tasks
        }
    
    def handle_get_results(self, request, session):
        agent_id = request.get('agent_id')
        
        results = self.db.get_agent_results(agent_id)
        
        self.audit_logger.log_event(
            session.user['id'],
            "results.view",
            "results",
            None,
            json.dumps({"agent_id": agent_id}),
            session.ip_address
        )
        
        return {
            "status": "success",
            "results": results
        }
    
    def handle_execute_module(self, request, session):
        module_name = request.get('module_name')
        module_args = request.get('args', {})
        agent_id = request.get('agent_id')
        
        from armory.module_manager import ModuleManager
        module_manager = ModuleManager(self.config, self.db)
        module = module_manager.get_module(module_name)
        
        if not module:
            return {
                "status": "error",
                "message": f"Module {module_name} not found"
            }
        
        result = module_manager.execute_module(module_name, module_args)
        
        # If agent_id is provided, create a task
        if agent_id and isinstance(result, dict) and 'code' in result:
            task_id = self.db.add_task(agent_id, result['code'])
            result['task_id'] = task_id
        
        self.audit_logger.log_event(
            session.user['id'],
            "modules.execute",
            "module",
            module_name,
            json.dumps({"args": module_args, "result": result}),
            session.ip_address
        )
        
        self.trigger_event("module_executed", {
            "module_name": module_name,
            "args": module_args,
            "result": result,
            "user_id": session.user['id']
        })
        
        return {
            "status": "success",
            "result": result
        }
    
    def handle_get_sessions(self, request, session):
        sessions = []
        for session_id, sess in self.active_sessions.items():
            sessions.append({
                "id": session_id,
                "username": sess.user['username'],
                "ip_address": sess.ip_address,
                "created_at": sess.created_at.isoformat(),
                "last_activity": sess.last_activity.isoformat()
            })
        
        return {
            "status": "success",
            "sessions": sessions
        }
    
    def handle_get_audit_log(self, request, session):
        limit = request.get('limit', 100)
        offset = request.get('offset', 0)
        
        logs = self.audit_logger.get_logs(limit, offset)
        
        return {
            "status": "success",
            "logs": logs
        }
    
    def handle_create_listener(self, request, session):
        try:
            type = request.get('type')
            if type == 'http':
                name = request.get('name')
                host = request.get('host', '0.0.0.0')
                port = request.get('port', 443)
                profile_name = request.get('profile_name', 'default')
                use_https = request.get('use_https', True)
                id = self.listener_manager.create_http_listener(name, host, port, profile_name, use_https)
                
                self.audit_logger.log_event(
                    session.user['id'],
                    "listeners.create",
                    "listener",
                    id,
                    json.dumps({"type": "http", "name": name, "host": host, "port": port, "profile_name": profile_name}),
                    session.ip_address
                )
                
                return {"status": "success", "listener_id": id}
            elif type == 'pivot':
                name = request.get('name')
                agent_id = request.get('agent_id')
                local_port = request.get('local_port')
                remote_host = request.get('remote_host')
                remote_port = request.get('remote_port')
                id = self.listener_manager.create_pivot_listener(name, agent_id, local_port, remote_host, remote_port)
                
                self.audit_logger.log_event(
                    session.user['id'],
                    "listeners.create",
                    "listener",
                    id,
                    json.dumps({"type": "pivot", "name": name, "agent_id": agent_id, "local_port": local_port, "remote_host": remote_host, "remote_port": remote_port}),
                    session.ip_address
                )
                
                return {"status": "success", "listener_id": id}
            else:
                return {"status": "error", "message": f"Unsupported listener type: {type}"}
        except Exception as e:
            self.logger.error(f"Error creating listener: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def handle_start_listener(self, request, session):
        try:
            id = request.get('listener_id')
            self.listener_manager.start_listener(id)
            
            self.audit_logger.log_event(
                session.user['id'],
                "listeners.start",
                "listener",
                id,
                None,
                session.ip_address
            )
            
            return {"status": "success"}
        except Exception as e:
            self.logger.error(f"Error starting listener: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def handle_stop_listener(self, request, session):
        try:
            id = request.get('listener_id')
            self.listener_manager.stop_listener(id)
            
            self.audit_logger.log_event(
                session.user['id'],
                "listeners.stop",
                "listener",
                id,
                None,
                session.ip_address
            )
            
            return {"status": "success"}
        except Exception as e:
            self.logger.error(f"Error stopping listener: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def handle_list_listeners(self, request, session):
        """Handle list_listeners request"""
        try:
            listeners = self.listener_manager.list_listeners()
            
            self.audit_logger.log_event(
                session.user['id'],
                "listeners.list",
                "listeners",
                None,
                None,
                session.ip_address
            )
            
            return {"status": "success", "listeners": listeners}
        except Exception as e:
            self.logger.error(f"Error listing listeners: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def trigger_event(self, event_type, data):
        """Trigger an event"""
        if event_type in self.event_handlers:
            try:
                self.event_handlers[event_type](data)
            except Exception as e:
                self.logger.error(f"Error handling event {event_type}: {str(e)}")
    
    def handle_agent_checkin(self, data):
        agent_id = data.get('agent_id')
        
        self.db.update_agent_checkin(agent_id)
        
        notification = {
            "type": "agent_checkin",
            "data": {
                "agent_id": agent_id,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        self.broadcast_notification(notification)
    
    def handle_task_result(self, data):
        task_id = data.get('task_id')
        result = data.get('result')
        
        self.db.update_task_status(task_id, "completed", result)
        
        notification = {
            "type": "task_result",
            "data": {
                "task_id": task_id,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        self.broadcast_notification(notification)
    
    def handle_user_login(self, data):
        user_id = data.get('user_id')
        
        self.db.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now(), user_id)
        )
        
        notification = {
            "type": "user_login",
            "data": {
                "user_id": user_id,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        self.broadcast_notification(notification)
    
    def handle_user_logout(self, data):
        """Handle user logout event"""
        user_id = data.get('user_id')
        session_id = data.get('session_id')
        
        # Deactivate session
        self.session_manager.deactivate_session(session_id)
        
        # Notify active sessions
        notification = {
            "type": "user_logout",
            "data": {
                "user_id": user_id,
                "session_id": session_id,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        self.broadcast_notification(notification)
    
    def handle_task_created(self, data):
        notification = {
            "type": "task_created",
            "data": {
                "task_id": data.get('task_id'),
                "agent_id": data.get('agent_id'),
                "user_id": data.get('user_id'),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        self.broadcast_notification(notification)
    
    def handle_module_executed(self, data):
        notification = {
            "type": "module_executed",
            "data": {
                "module_name": data.get('module_name'),
                "user_id": data.get('user_id'),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        self.broadcast_notification(notification)
    
    def broadcast_notification(self, notification):
        for session_id, session in self.active_sessions.items():
            try:
                pass
            except Exception as e:
                self.logger.error(f"Error broadcasting notification to session {session_id}: {str(e)}")
    
    def server_loop(self):
        try:
            while self.running:
                time.sleep(1)
                
                self.session_manager.cleanup_inactive_sessions()
                
                self.cleanup_inactive_agents

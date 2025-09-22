from flask import Flask, render_template, request, jsonify
import re
import nltk
import json
import time
import random
import requests
from datetime import datetime, timedelta
import  os

app = Flask(__name__)

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

# Mock Healthcare Data
MOCK_PATIENTS = {
    "P001": {"name": "John Doe", "age": 45, "diagnosis": "Hypertension", "authorized_users": ["doctor1", "nurse1"], "last_accessed": None},
    "P002": {"name": "Jane Smith", "age": 32, "diagnosis": "Diabetes", "authorized_users": ["doctor2", "nurse2"], "last_accessed": None},
    "P003": {"name": "Bob Johnson", "age": 67, "diagnosis": "Heart Disease", "authorized_users": ["doctor1"], "last_accessed": None}
}

MOCK_USERS = {
    "doctor1": {"password": "secure123", "role": "doctor", "active": True, "login_attempts": 0},
    "nurse1": {"password": "nurse456", "role": "nurse", "active": True, "login_attempts": 0},
    "doctor2": {"password": "doc789", "role": "doctor", "active": True, "login_attempts": 0},
    "invalid_user": {"password": "wrong", "role": "user", "active": False, "login_attempts": 3}
}

AUDIT_LOGS = []
ACTIVE_SESSIONS = {}

def log_audit_event(user, event_type, description, ip_address="127.0.0.1"):
    event = {
        'id': len(AUDIT_LOGS) + 1,
        'timestamp': datetime.now().isoformat(),
        'user': user,
        'event_type': event_type,
        'description': description,
        'ip_address': ip_address
    }
    AUDIT_LOGS.append(event)
    print(f"AUDIT: {event['timestamp']} - {user} - {event_type}")

class HealthcareTestGenerator:
    def __init__(self):
        self.compliance_keywords = {
            'hipaa': ['patient', 'medical', 'health', 'record', 'privacy', 'phi'],
            'authentication': ['login', 'password', 'user', 'access', 'credential', 'authenticate'],
            'security': ['encrypt', 'secure', 'protect', 'audit', 'log'],
            'data_integrity': ['data', 'database', 'store', 'save', 'retrieve']
        }
    
    def extract_requirements(self, text):
        sentences = nltk.sent_tokenize(text)
        requirements = []
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) > 15:
                requirements.append(sentence)
        return requirements
    
    def identify_compliance_tags(self, requirement_text):
        tags = []
        text_lower = requirement_text.lower()
        for compliance_type, keywords in self.compliance_keywords.items():
            if any(keyword in text_lower for keyword in keywords):
                if compliance_type == 'hipaa':
                    tags.append('HIPAA')
                elif compliance_type == 'authentication':
                    tags.append('Authentication')
                elif compliance_type == 'security':
                    tags.append('Security')
                elif compliance_type == 'data_integrity':
                    tags.append('Data Integrity')
        if not tags:
            tags.append('General')
        return list(set(tags))
    
    def generate_executable_test_steps(self, requirement):
        req_lower = requirement.lower()
        steps = []
        
        if 'authenticate' in req_lower or 'login' in req_lower:
            steps = [
                {'action': 'api_call', 'method': 'POST', 'endpoint': '/api/auth/login', 'data': {'username': 'doctor1', 'password': 'secure123'}, 'expected_status': 200, 'description': 'Test valid authentication'},
                {'action': 'api_call', 'method': 'POST', 'endpoint': '/api/auth/login', 'data': {'username': 'invalid_user', 'password': 'wrong'}, 'expected_status': 401, 'description': 'Test invalid authentication'}
            ]
        elif 'patient' in req_lower:
            steps = [
                {'action': 'authenticate', 'user': 'doctor1', 'description': 'Authenticate as doctor'},
                {'action': 'api_call', 'method': 'GET', 'endpoint': '/api/patients/P001', 'expected_status': 200, 'description': 'Access authorized patient'},
                {'action': 'api_call', 'method': 'GET', 'endpoint': '/api/patients/P002', 'expected_status': 403, 'description': 'Test unauthorized access'}
            ]
        elif 'encrypt' in req_lower:
            steps = [
                {'action': 'api_call', 'method': 'GET', 'endpoint': '/api/encryption/status', 'expected_status': 200, 'description': 'Verify encryption status'}
            ]
        elif 'audit' in req_lower:
            steps = [
                {'action': 'api_call', 'method': 'GET', 'endpoint': '/api/audit/logs', 'expected_status': 200, 'description': 'Verify audit logs'}
            ]
        else:
            steps = [
                {'action': 'api_call', 'method': 'GET', 'endpoint': '/api/health', 'expected_status': 200, 'description': 'Test system health'}
            ]
        return steps
    
    def generate_test_cases(self, requirements_text):
        requirements = self.extract_requirements(requirements_text)
        test_cases = []
        
        for idx, requirement in enumerate(requirements):
            test_case = {
                'id': f'TC_{idx+1:03d}',
                'title': f'Test: {requirement[:60]}{"..." if len(requirement) > 60 else ""}',
                'requirement': requirement,
                'test_steps': self.generate_executable_test_steps(requirement),
                'expected_result': self.generate_expected_result(requirement),
                'priority': 'High' if any(word in requirement.lower() for word in ['patient', 'security', 'hipaa', 'encrypt']) else 'Medium',
                'compliance_tags': self.identify_compliance_tags(requirement),
                'executable': True
            }
            test_cases.append(test_case)
        return test_cases
    
    def generate_expected_result(self, requirement):
        req_lower = requirement.lower()
        if 'authenticate' in req_lower:
            return 'System validates credentials and maintains secure sessions'
        elif 'patient' in req_lower:
            return 'Patient data accessible only to authorized users with audit logging'
        elif 'encrypt' in req_lower:
            return 'All data encrypted during transmission and storage'
        elif 'audit' in req_lower:
            return 'Complete audit trail maintained for all activities'
        else:
            return 'System functions according to requirements with compliance validation'

# Mock API Endpoints
@app.route('/api/health', methods=['GET'])
def health_check():
    log_audit_event('system', 'health_check', 'System health checked')
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    
    log_audit_event(username, 'login_attempt', f'Login attempt for {username}')
    
    if username in MOCK_USERS and MOCK_USERS[username]['password'] == password and MOCK_USERS[username]['active']:
        session_id = f"sess_{random.randint(1000, 9999)}"
        ACTIVE_SESSIONS[session_id] = {'user': username, 'role': MOCK_USERS[username]['role'], 'login_time': datetime.now()}
        log_audit_event(username, 'login_success', f'Successful login')
        return jsonify({'status': 'success', 'token': session_id, 'role': MOCK_USERS[username]['role']}), 200
    else:
        log_audit_event(username, 'login_failed', f'Failed login attempt')
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

@app.route('/api/patients/<patient_id>', methods=['GET'])
def get_patient(patient_id):
    auth_header = request.headers.get('Authorization', '')
    session_id = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else None
    
    if not session_id or session_id not in ACTIVE_SESSIONS:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    user = ACTIVE_SESSIONS[session_id]['user']
    log_audit_event(user, 'patient_access_attempt', f'Attempted access to patient {patient_id}')
    
    if patient_id not in MOCK_PATIENTS:
        return jsonify({'status': 'error', 'message': 'Patient not found'}), 404
    
    patient = MOCK_PATIENTS[patient_id]
    if user not in patient['authorized_users']:
        log_audit_event(user, 'unauthorized_access', f'Unauthorized access to patient {patient_id}')
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    
    log_audit_event(user, 'patient_accessed', f'Patient {patient_id} accessed successfully')
    return jsonify({**patient, 'encryption': 'AES-256', 'accessed_by': user, 'access_time': datetime.now().isoformat()}), 200

@app.route('/api/audit/logs', methods=['GET'])
def get_audit_logs():
    auth_header = request.headers.get('Authorization', '')
    session_id = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else None
    
    if not session_id or session_id not in ACTIVE_SESSIONS:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    return jsonify({'logs': AUDIT_LOGS[-10:], 'total_logs': len(AUDIT_LOGS)}), 200

@app.route('/api/encryption/status', methods=['GET'])
def encryption_status():
    return jsonify({'status': 'enabled', 'algorithm': 'AES-256', 'compliance': 'HIPAA-compliant'})

# Test Execution Engine
class TestExecutor:
    def __init__(self):
        self.base_url = 'https://genaiexchangehackathon-2.onrender.com'
        self.current_token = None
    
    def execute_test_suite(self, test_cases):
        results = {'test_results': [], 'summary': {'total_tests': len(test_cases), 'passed': 0, 'failed': 0}}
        
        for test_case in test_cases:
            result = self.execute_single_test(test_case)
            results['test_results'].append(result)
            if result['status'] == 'PASSED':
                results['summary']['passed'] += 1
            else:
                results['summary']['failed'] += 1
        
        return results
    
    def execute_single_test(self, test_case):
        result = {'test_id': test_case['id'], 'title': test_case['title'], 'status': 'RUNNING', 'step_results': []}
        
        for step_idx, step in enumerate(test_case['test_steps']):
            step_result = self.execute_test_step(step, step_idx + 1)
            result['step_results'].append(step_result)
            time.sleep(0.5)  # Simulate processing
        
        passed_steps = sum(1 for step in result['step_results'] if step['passed'])
        result['status'] = 'PASSED' if passed_steps == len(result['step_results']) else 'FAILED'
        return result
    
    def execute_test_step(self, step, step_number):
        step_result = {'step_number': step_number, 'action': step['action'], 'description': step.get('description', ''), 'passed': False, 'message': ''}
        
        try:
            if step['action'] == 'api_call':
                url = self.base_url + step['endpoint']
                headers = {'Content-Type': 'application/json'}
                
                if self.current_token:
                    headers['Authorization'] = f"Bearer {self.current_token}"
                
                if step['method'] == 'GET':
                    response = requests.get(url, headers=headers, timeout=5)
                elif step['method'] == 'POST':
                    response = requests.post(url, json=step.get('data', {}), headers=headers, timeout=5)
                
                if response.status_code == step['expected_status']:
                    step_result['passed'] = True
                    step_result['message'] = f"API call successful (Status: {response.status_code})"
                    
                    # Store token if received
                    if 'token' in response.text:
                        try:
                            data = response.json()
                            if 'token' in data:
                                self.current_token = data['token']
                        except:
                            pass
                else:
                    step_result['message'] = f"Expected {step['expected_status']}, got {response.status_code}"
                    
            elif step['action'] == 'authenticate':
                user = step.get('user')
                if user and user in MOCK_USERS:
                    login_data = {'username': user, 'password': MOCK_USERS[user]['password']}
                    response = requests.post(f"{self.base_url}/api/auth/login", json=login_data, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        self.current_token = data.get('token')
                        step_result['passed'] = True
                        step_result['message'] = f"Successfully authenticated {user}"
                    else:
                        step_result['message'] = f"Authentication failed for {user}"
            else:
                step_result['passed'] = True
                step_result['message'] = f"Step executed: {step['action']}"
                
        except Exception as e:
            step_result['message'] = f"Error: {str(e)}"
        
        return step_result

# Initialize components
test_generator = HealthcareTestGenerator()
test_executor = TestExecutor()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate_tests():
    try:
        requirements_text = request.form.get('requirements', '').strip()
        if not requirements_text:
            return jsonify({'success': False, 'error': 'Please provide requirements text'})
        
        test_cases = test_generator.generate_test_cases(requirements_text)
        total_requirements = len(test_generator.extract_requirements(requirements_text))
        compliance_areas = set()
        for tc in test_cases:
            compliance_areas.update(tc['compliance_tags'])
        
        summary = {
            'total_test_cases': len(test_cases),
            'total_requirements': total_requirements,
            'compliance_areas': len(compliance_areas),
            'high_priority_tests': len([tc for tc in test_cases if tc['priority'] == 'High']),
            'executable_tests': len([tc for tc in test_cases if tc.get('executable', False)]),
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return jsonify({'success': True, 'test_cases': test_cases, 'summary': summary})
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error generating test cases: {str(e)}'})

@app.route('/execute_tests', methods=['POST'])
def execute_tests():
    try:
        data = request.get_json()
        test_cases = data.get('test_cases', [])
        
        if not test_cases:
            return jsonify({'success': False, 'error': 'No test cases provided'})
        
        execution_results = test_executor.execute_test_suite(test_cases)
        return jsonify({'success': True, 'execution_results': execution_results})
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error executing tests: {str(e)}'})

if __name__ == '__main__':
    log_audit_event('system', 'startup', 'Healthcare Test System initialized')
    print("🏥 Healthcare AI Test Generator with Real Execution Engine")
    print("🚀 Starting server with mock APIs and test execution...")
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)


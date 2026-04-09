import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../../api/client';
import { login as loginApi } from '../../api/auth';
import useAuthStore from '../../stores/useAuthStore';

const STEPS = ['welcome', 'environment', 'login', 'complete'];

function StepIndicator({ current, steps }) {
  return (
    <div className="flex items-center justify-center gap-2 mb-8">
      {steps.map((s, i) => (
        <div key={s} className={`w-3 h-3 rounded-full ${i <= current ? 'bg-blue-500' : 'bg-gray-600'}`} />
      ))}
    </div>
  );
}

function WelcomeStep({ onNext }) {
  return (
    <div className="text-center">
      <div className="text-6xl mb-4">🐕</div>
      <h1 className="text-3xl font-bold text-white mb-2">Welcome to REX-BOT-AI</h1>
      <p className="text-gray-400 mb-6 max-w-md mx-auto">
        Your autonomous AI security agent for home and small business networks.
        Let's get you set up in a few quick steps.
      </p>
      <button onClick={onNext} className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3 rounded-lg font-medium">
        Get Started
      </button>
    </div>
  );
}

function EnvironmentStep({ onNext }) {
  const [checks, setChecks] = useState({ redis: null, ollama: null, chromadb: null, api: null });

  useEffect(() => {
    // Use the dedicated /env-check endpoint which probes all services
    // without requiring authentication.
    const runChecks = async () => {
      try {
        const res = await api.get('/env-check', { timeout: 10000 });
        const d = res.data;
        setChecks({
          api: d.api ?? true,
          redis: d.redis ?? false,
          ollama: d.ollama ?? false,
          chromadb: d.chromadb ?? false,
        });
      } catch (err) {
        // API itself is unreachable
        setChecks({ api: false, redis: false, ollama: false, chromadb: false });
      }
    };
    runChecks();
  }, []);

  const allDone = checks.api !== null && checks.redis !== null && checks.ollama !== null && checks.chromadb !== null;

  const Check = ({ label, status }) => (
    <div className="flex items-center gap-3 py-2">
      <span className={`w-3 h-3 rounded-full ${status === true ? 'bg-green-500' : status === false ? 'bg-amber-500' : 'bg-gray-500 animate-pulse'}`} />
      <span className="text-gray-300">{label}</span>
      <span className="text-xs text-gray-500 ml-auto">
        {status === true ? 'OK' : status === false ? 'Not available (optional)' : 'Checking...'}
      </span>
    </div>
  );

  return (
    <div>
      <h2 className="text-xl font-bold text-white mb-4">Environment Check</h2>
      <p className="text-gray-400 mb-4 text-sm">Checking your system dependencies...</p>
      <div className="bg-gray-800 rounded-lg p-4 mb-6">
        <Check label="Dashboard API" status={checks.api} />
        <Check label="Redis (event bus)" status={checks.redis} />
        <Check label="Ollama (AI engine)" status={checks.ollama} />
        <Check label="ChromaDB (vector memory)" status={checks.chromadb} />
      </div>
      {checks.redis === false && (
        <p className="text-amber-400 text-xs mb-4">
          Redis is not available. REX will run in degraded mode. Install with: sudo apt install redis-server
        </p>
      )}
      {checks.ollama === false && (
        <p className="text-amber-400 text-xs mb-4">
          Ollama is not available. REX will use rules-only classification (no AI). Install from ollama.com
        </p>
      )}
      <button onClick={onNext} className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg">
        Continue
      </button>
    </div>
  );
}

function LoginStep({ onNext, onPasswordCapture }) {
  const [authState, setAuthState] = useState(null); // null=loading, 'setup_required', 'active'
  const [password, setPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const setToken = useAuthStore(s => s.setToken);

  useEffect(() => {
    api.get('/auth/auth-state').then(res => {
      setAuthState(res.data?.state || 'active');
    }).catch(() => {
      setAuthState('active');
    });
  }, []);

  const handleLogin = async () => {
    setLoading(true);
    setError('');
    try {
      const { token } = await loginApi(password);
      setToken(token);
      onPasswordCapture(password);
      onNext();
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || 'Login failed');
    }
    setLoading(false);
  };

  const handleSetup = async () => {
    if (newPassword.length < 8) { setError('Password must be at least 8 characters'); return; }
    if (newPassword !== confirmPassword) { setError('Passwords do not match'); return; }
    setLoading(true);
    setError('');
    try {
      const res = await api.post('/auth/setup', { new_password: newPassword });
      const token = res.data?.access_token || '';
      if (token) {
        setToken(token);
        onPasswordCapture(newPassword);
        onNext();
      } else {
        setError('Server returned an empty token');
      }
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || 'Setup failed');
    }
    setLoading(false);
  };

  if (authState === null) {
    return (
      <div className="text-center py-4">
        <div className="text-gray-400 text-sm">Checking auth state...</div>
      </div>
    );
  }

  if (authState === 'setup_required') {
    return (
      <div>
        <h2 className="text-xl font-bold text-white mb-4">Create Admin Password</h2>
        <div className="bg-gray-800 rounded-lg p-4 mb-4">
          <p className="text-gray-300 text-sm mb-3">
            This is your first time running REX. Create a password for the admin account.
          </p>
        </div>
        <div className="space-y-3">
          <input
            type="password"
            placeholder="New password (min 8 characters)"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            autoComplete="new-password"
            className="w-full bg-gray-700 text-white rounded px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <input
            type="password"
            placeholder="Confirm password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSetup()}
            autoComplete="new-password"
            className="w-full bg-gray-700 text-white rounded px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          {error && <p className="text-red-400 text-xs">{error}</p>}
          <button
            onClick={handleSetup}
            disabled={loading || !newPassword || !confirmPassword}
            className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg disabled:opacity-50"
          >
            {loading ? 'Creating...' : 'Create Password & Continue'}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-xl font-bold text-white mb-4">Login</h2>
      <div className="bg-gray-800 rounded-lg p-4 mb-4">
        <p className="text-gray-300 text-sm mb-3">
          Enter your admin password to continue.
        </p>
      </div>
      <div className="space-y-3">
        <input
          type="password"
          placeholder="Enter admin password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
          className="w-full bg-gray-700 text-white rounded px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        {error && <p className="text-red-400 text-xs">{error}</p>}
        <button
          onClick={handleLogin}
          disabled={loading || !password}
          className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg disabled:opacity-50"
        >
          {loading ? 'Logging in...' : 'Login'}
        </button>
      </div>
    </div>
  );
}

function PasswordStep({ onNext, loginPassword }) {
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleChange = async () => {
    if (newPw !== confirmPw) { setError('Passwords do not match'); return; }
    if (newPw.length < 4) { setError('Password too short'); return; }
    setLoading(true);
    setError('');
    try {
      await api.post('/auth/change-password', { old_password: loginPassword, new_password: newPw });
      onNext();
    } catch (e) {
      setError(e?.response?.data?.detail || 'Failed to change password');
    }
    setLoading(false);
  };

  return (
    <div>
      <h2 className="text-xl font-bold text-white mb-4">Change Password</h2>
      <p className="text-gray-400 text-sm mb-4">We recommend changing the default password.</p>
      <div className="space-y-3">
        <input type="password" placeholder="New password" value={newPw} onChange={e => setNewPw(e.target.value)}
          className="w-full bg-gray-700 text-white rounded px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
        <input type="password" placeholder="Confirm password" value={confirmPw} onChange={e => setConfirmPw(e.target.value)}
          className="w-full bg-gray-700 text-white rounded px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
        {error && <p className="text-red-400 text-xs">{error}</p>}
        <div className="flex gap-3">
          <button onClick={handleChange} disabled={loading}
            className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg disabled:opacity-50">
            {loading ? 'Changing...' : 'Change Password'}
          </button>
          <button onClick={onNext} className="text-gray-400 hover:text-gray-300 text-sm">
            Skip (not recommended)
          </button>
        </div>
      </div>
    </div>
  );
}

function CompleteStep() {
  const navigate = useNavigate();
  const handleFinish = () => {
    localStorage.setItem('rex_setup_complete', Date.now().toString());
    navigate('/overview');
  };
  return (
    <div className="text-center">
      <div className="text-6xl mb-4">🎉</div>
      <h2 className="text-2xl font-bold text-white mb-2">REX is Ready!</h2>
      <p className="text-gray-400 mb-6">Your network security agent is protecting your network.</p>
      <button onClick={handleFinish} className="bg-green-600 hover:bg-green-700 text-white px-8 py-3 rounded-lg font-medium">
        Go to Dashboard
      </button>
    </div>
  );
}

export default function SetupWizard() {
  const [step, setStep] = useState(0);
  const [loginPassword, setLoginPassword] = useState('');
  const next = () => setStep(s => Math.min(s + 1, STEPS.length - 1));

  const components = [
    <WelcomeStep onNext={next} />,
    <EnvironmentStep onNext={next} />,
    <LoginStep onNext={next} onPasswordCapture={setLoginPassword} />,
    <CompleteStep />,
  ];

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div className="w-full max-w-lg">
        <StepIndicator current={step} steps={STEPS} />
        {components[step]}
      </div>
    </div>
  );
}

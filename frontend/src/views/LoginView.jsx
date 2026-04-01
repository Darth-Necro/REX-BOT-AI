import React, { useState, useEffect } from 'react';
import useSystemStore from '../stores/useSystemStore';
import api from '../api/client';

export default function LoginView() {
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [firstBoot, setFirstBoot] = useState(null);
    const setToken = useSystemStore((s) => s.setToken);

    useEffect(() => {
        // Check for first-boot password
        api.get('/auth/first-boot')
            .then((res) => {
                if (res.data.first_boot && res.data.password) {
                    setFirstBoot(res.data);
                    setPassword(res.data.password);
                }
            })
            .catch(() => {
                // Backend unreachable -- ignore
            });
    }, []);

    const handleLogin = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            const res = await api.post('/auth/login', { password });
            const { access_token } = res.data;
            if (!access_token) { setError('Invalid response from server'); return; }
            setToken(access_token);
        } catch (err) {
            setError(err.response?.data?.detail || 'Invalid password or REX is not running');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-rex-bg flex items-center justify-center">
            <div className="bg-rex-surface rounded-xl p-8 w-full max-w-sm shadow-xl">
                <pre className="text-rex-accent text-center text-2xl mb-4 select-none">
{`  /\\_/\\
 ( o.o )
  > ^ <`}
                </pre>
                <h1 className="text-xl font-bold text-center text-rex-text mb-6">REX-BOT-AI</h1>

                {firstBoot && (
                    <div className="mb-4 p-3 bg-rex-bg border border-rex-accent rounded-lg">
                        <p className="text-rex-accent font-semibold text-sm mb-1">First Boot - Admin Password</p>
                        <p className="text-rex-text font-mono text-lg text-center my-2 select-all">{firstBoot.password}</p>
                        <p className="text-rex-muted text-xs text-center">Write this down. It will not be shown again.</p>
                    </div>
                )}

                <form onSubmit={handleLogin} className="space-y-4">
                    <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Admin password"
                        className="w-full px-4 py-3 bg-rex-bg border border-rex-card rounded-lg text-rex-text focus:border-rex-accent focus:outline-none"
                        autoFocus={!firstBoot}
                    />
                    {error && <p className="text-rex-threat text-sm">{error}</p>}
                    <button
                        type="submit"
                        disabled={loading || !password}
                        className="w-full py-3 bg-rex-accent text-white rounded-lg font-medium hover:bg-blue-600 disabled:opacity-50 transition-colors"
                    >
                        {loading ? 'Connecting...' : 'Log In'}
                    </button>
                </form>
                <p className="text-xs text-rex-muted text-center mt-4">
                    Network monitoring active
                </p>
            </div>
        </div>
    );
}

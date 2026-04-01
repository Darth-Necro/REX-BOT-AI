/**
 * useDangerConfirm — hook for gating destructive actions behind a
 * confirmation modal. Returns state + handlers that plug directly
 * into <DangerConfirmModal />.
 */
import { useState, useCallback } from 'react';

/**
 * @returns {{
 *   isOpen: boolean,
 *   title: string,
 *   description: string,
 *   impact: string,
 *   open: (opts: { title: string, description: string, impact?: string, onConfirm: () => void }) => void,
 *   close: () => void,
 *   confirm: () => void,
 * }}
 */
export default function useDangerConfirm() {
  const [state, setState] = useState({
    isOpen: false,
    title: '',
    description: '',
    impact: '',
    onConfirm: null,
  });

  const open = useCallback(({ title, description, impact = '', onConfirm }) => {
    setState({ isOpen: true, title, description, impact, onConfirm });
  }, []);

  const close = useCallback(() => {
    setState((s) => ({ ...s, isOpen: false, onConfirm: null }));
  }, []);

  const confirm = useCallback(() => {
    if (typeof state.onConfirm === 'function') {
      state.onConfirm();
    }
    close();
  }, [state.onConfirm, close]);

  return {
    isOpen: state.isOpen,
    title: state.title,
    description: state.description,
    impact: state.impact,
    open,
    close,
    confirm,
  };
}

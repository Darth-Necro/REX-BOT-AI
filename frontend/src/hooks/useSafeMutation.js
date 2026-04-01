/**
 * useSafeMutation — standardise pending/success/error feedback for mutations.
 *
 * Wraps an async action with automatic toast lifecycle:
 *   1. Shows a "pending" toast when the action starts.
 *   2. Replaces it with "success" or "error" on resolution.
 *
 * Callers get back { mutate, isPending } so they can disable buttons.
 *
 * Usage:
 *   const { mutate: saveSettings, isPending } = useSafeMutation(
 *     store.saveSettings,
 *     { pending: 'Saving...', success: 'Settings saved', error: 'Save failed' }
 *   );
 */
import { useState, useCallback, useRef } from 'react';
import useUiStore from '../stores/useUiStore';

/**
 * @param {(...args: any[]) => Promise<any>} action  Async function to execute.
 * @param {{
 *   pending?: string,
 *   success?: string,
 *   error?: string,
 *   unsupported?: string,
 * }} messages  Toast messages for each lifecycle phase.
 * @param {{ onSuccess?: (result: any) => void, onError?: (err: Error) => void }} callbacks
 * @returns {{ mutate: (...args: any[]) => Promise<any>, isPending: boolean }}
 */
export default function useSafeMutation(action, messages = {}, callbacks = {}) {
  const [isPending, setIsPending] = useState(false);
  const toastIdRef = useRef(null);

  const pushToast = useUiStore((s) => s.pushToast);
  const replaceToast = useUiStore((s) => s.replaceToast);
  const dismissToast = useUiStore((s) => s.dismissToast);

  const mutate = useCallback(
    async (...args) => {
      if (isPending) return undefined;
      setIsPending(true);

      // Show pending toast
      if (messages.pending) {
        toastIdRef.current = pushToast({
          type: 'pending',
          message: messages.pending,
        });
      }

      try {
        const result = await action(...args);

        // Replace pending toast with success
        if (toastIdRef.current != null && messages.success) {
          replaceToast(toastIdRef.current, {
            type: 'success',
            message: messages.success,
          });
        } else if (toastIdRef.current != null) {
          dismissToast(toastIdRef.current);
        }

        toastIdRef.current = null;
        setIsPending(false);
        callbacks.onSuccess?.(result);
        return result;
      } catch (err) {
        // Replace pending toast with error
        const errorMsg =
          messages.error ||
          err?.message ||
          'An unexpected error occurred';

        if (toastIdRef.current != null) {
          replaceToast(toastIdRef.current, {
            type: 'error',
            message: errorMsg,
          });
        } else {
          pushToast({ type: 'error', message: errorMsg });
        }

        toastIdRef.current = null;
        setIsPending(false);
        callbacks.onError?.(err);
        return undefined;
      }
    },
    [action, messages, callbacks, isPending, pushToast, replaceToast, dismissToast]
  );

  return { mutate, isPending };
}

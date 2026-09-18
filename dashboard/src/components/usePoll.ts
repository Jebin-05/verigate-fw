/** Poll an async loader on an interval; exposes data, error and a manual refresh. */
import { useCallback, useEffect, useState } from 'react';

export function usePoll<T>(loader: () => Promise<T>, intervalMs = 3000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refresh = useCallback(async () => {
    try {
      setData(await loader());
      setError(null);
    } catch (err) {
      setError(String(err));
    }
  }, [loader]);
  useEffect(() => {
    void refresh();
    const id = setInterval(() => void refresh(), intervalMs);
    return () => clearInterval(id);
  }, [refresh, intervalMs]);
  return { data, error, refresh };
}

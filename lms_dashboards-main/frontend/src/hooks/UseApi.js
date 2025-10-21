import { useState, useEffect } from 'react';

const useApi = (apiCall, options = {}) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const refetch = async () => {
    if (!apiCall) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const result = await apiCall();
      setData(result.data || result);
    } catch (err) {
      setError(err.message || 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refetch();
  }, []);

  return { data, loading, error, refetch };
};

export default useApi;
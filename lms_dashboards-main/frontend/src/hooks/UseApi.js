import { useState, useEffect, useCallback, useRef } from 'react';

export const useApi = (apiCall, dependencies = []) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const abortControllerRef = useRef(null);

  const fetchData = useCallback(async () => {
    // Cancel previous request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    
    abortControllerRef.current = new AbortController();

    try {
      setLoading(true);
      setError(null);
      const result = await apiCall();
      
      if (result.success) {
        setData(result.data);
      } else {
        setError(result.error || 'Something went wrong');
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        setError(err.message || 'An unexpected error occurred');
      }
    } finally {
      setLoading(false);
    }
  }, [apiCall]);

  useEffect(() => {
    fetchData();
    
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, dependencies);

  // Clear error helper
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  return { 
    data, 
    loading, 
    error, 
    refetch: fetchData,
    setData,
    clearError
  };
};

// Enhanced paginated hook with abort controller
export const usePaginatedApi = (apiCall, initialPage = 1, pageSize = 10) => {
  const [page, setPage] = useState(initialPage);
  const [allData, setAllData] = useState([]);
  const [hasMore, setHasMore] = useState(true);
  const abortControllerRef = useRef(null);

  const { data, loading, error, refetch } = useApi(
    useCallback(() => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      abortControllerRef.current = new AbortController();
      return apiCall({ page, page_size: pageSize });
    }, [page, pageSize, apiCall]),
    [page, pageSize]
  );

  useEffect(() => {
    if (data) {
      if (page === 1) {
        setAllData(data);
      } else {
        setAllData(prev => [...prev, ...data]);
      }
      setHasMore(data.length === pageSize);
    }
  }, [data, page, pageSize]);

  const loadMore = useCallback(() => {
    if (!loading && hasMore) {
      setPage(prev => prev + 1);
    }
  }, [loading, hasMore]);

  const reset = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    setPage(1);
    setAllData([]);
    setHasMore(true);
  }, []);

  const refetchWithReset = useCallback(() => {
    reset();
    refetch();
  }, [reset, refetch]);

  return {
    data: allData,
    loading,
    error,
    hasMore,
    loadMore,
    reset,
    refetch: refetchWithReset,
    currentPage: page
  };
};
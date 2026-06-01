import { useCallback } from 'react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch } from '@/app/hooks';
import { extractApiErrorMessage } from '../utils/errorUtils';
import { useLoginMutation } from '../api/authApi';
import { setCredentials } from '../store/authSlice';
import type { LoginRequest } from '../types/authTypes';

export function useLogin() {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const [login, state] = useLoginMutation();

  const submit = useCallback(
    async (values: LoginRequest) => {
      try {
        const result = await login(values).unwrap();
        dispatch(setCredentials({ token: result.accessToken, user: result.user }));
        toast.success(`Welcome back, ${result.user.firstName}`);
        navigate('/', { replace: true });
      } catch (err) {
        toast.error(extractApiErrorMessage(err, 'Login failed'));
      }
    },
    [dispatch, login, navigate],
  );

  return { submit, isLoading: state.isLoading };
}

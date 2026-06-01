import { TOURS_FIXTURE } from '@/shared/fixtures';
import { sortByDate } from '../utils/clToursUtils';

export function useTours() {
  return { tours: sortByDate(TOURS_FIXTURE), isUsingFixture: true };
}

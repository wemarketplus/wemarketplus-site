import { Plus } from 'lucide-react';
import { Button } from '@/shared/ui/core';
import { ToursList } from '../components/ToursList';
import { BookTourModal } from '../components/BookTourModal';
import { useTours } from '../hooks/useTours';
import { useBookTour } from '../hooks/useBookTour';

export function ClToursPage() {
  const { tours, isUsingFixture } = useTours();
  const { open, isSaving, openModal, close, submit } = useBookTour();

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">Tour scheduler</h1>
          <p className="text-sm text-muted">
            {tours.length} upcoming tours
            {isUsingFixture && (
              <span className="ml-2 rounded-pill bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                Preview data
              </span>
            )}
          </p>
        </div>
        <Button onClick={openModal}>
          <Plus className="h-4 w-4" /> Book tour
        </Button>
      </header>
      <ToursList tours={tours} />

      <BookTourModal open={open} isSaving={isSaving} onClose={close} onSubmit={submit} />
    </div>
  );
}

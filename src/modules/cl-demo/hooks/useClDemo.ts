// Orchestration hook for the CommunityLink demo: exposes the slice state and a
// bound set of action dispatchers (the demo's "business logic" entry point), so
// components stay presentational and never touch dispatch/selectors directly.
import { useMemo } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { clDemoActions } from '../store/clDemoSlice';

export function useClDemo() {
  const dispatch = useAppDispatch();
  const state = useAppSelector((s) => s.clDemo);

  const actions = useMemo(
    () => ({
      setTab: (tab: Parameters<typeof clDemoActions.setTab>[0]) => dispatch(clDemoActions.setTab(tab)),
      setRole: (role: Parameters<typeof clDemoActions.setRole>[0]) => dispatch(clDemoActions.setRole(role)),
      toast: (message: string, error = false) => dispatch(clDemoActions.showToast(message, error)),
      hideToast: () => dispatch(clDemoActions.hideToast()),
      addLead: (input: Parameters<typeof clDemoActions.addLead>[0]) => dispatch(clDemoActions.addLead(input)),
      saveLeadEdit: (input: Parameters<typeof clDemoActions.saveLeadEdit>[0]) => dispatch(clDemoActions.saveLeadEdit(input)),
      deleteLead: (id: number) => dispatch(clDemoActions.deleteLead(id)),
      openLead: (id: number) => dispatch(clDemoActions.openLead(id)),
      closeLead: () => dispatch(clDemoActions.closeLead()),
      addReferral: (input: Parameters<typeof clDemoActions.addReferral>[0]) => dispatch(clDemoActions.addReferral(input)),
      logRefVisit: (id: number) => dispatch(clDemoActions.logRefVisit(id)),
      deleteRef: (id: number) => dispatch(clDemoActions.deleteRef(id)),
      setTourForm: (open: boolean) => dispatch(clDemoActions.setTourForm(open)),
      addTour: (input: Parameters<typeof clDemoActions.addTour>[0]) => dispatch(clDemoActions.addTour(input)),
      toggleTourStatus: (id: number) => dispatch(clDemoActions.toggleTourStatus(id)),
      addOutreach: (input: Parameters<typeof clDemoActions.addOutreach>[0]) => dispatch(clDemoActions.addOutreach(input)),
      addMileage: (input: Parameters<typeof clDemoActions.addMileage>[0]) => dispatch(clDemoActions.addMileage(input)),
      deleteMileage: (id: number) => dispatch(clDemoActions.deleteMileage(id)),
      setTaskForm: (open: boolean) => dispatch(clDemoActions.setTaskForm(open)),
      addTask: (input: Parameters<typeof clDemoActions.addTask>[0]) => dispatch(clDemoActions.addTask(input)),
      toggleTask: (id: number, done: boolean) => dispatch(clDemoActions.toggleTask({ id, done })),
      deleteTask: (id: number) => dispatch(clDemoActions.deleteTask(id)),
      addNote: (input: Parameters<typeof clDemoActions.addNote>[0]) => dispatch(clDemoActions.addNote(input)),
    }),
    [dispatch],
  );

  return { ...state, actions };
}

import { AddLeadModal } from './AddLeadModal';
import { AddMrModal } from './AddMrModal';
import { AddSourceModal } from './AddSourceModal';
import { AddTicketModal } from './AddTicketModal';
import { AddUnitModal } from './AddUnitModal';
import { AssignTaskModal } from './AssignTaskModal';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Renders the currently-open modal (reference's unified modal system).
export function MaxModalHost() {
  const { openModal } = useMaxDemo();
  switch (openModal) {
    case 'addLead': return <AddLeadModal />;
    case 'addSource': return <AddSourceModal />;
    case 'addUnit': return <AddUnitModal />;
    case 'addTicket': return <AddTicketModal />;
    case 'addMr': return <AddMrModal />;
    case 'addTask': return <AssignTaskModal />;
    default: return null;
  }
}

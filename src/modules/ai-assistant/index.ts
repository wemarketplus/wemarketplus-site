export { AiAssistantPage } from './pages/AiAssistantPage';
export { PlaybookGeneratorPage } from './pages/PlaybookGeneratorPage';
// The floating Copilot, mounted once in DashboardLayout. Renders nothing except
// for a CommunityLink field role — see the component for why it is a floating
// button rather than a nav row.
export { CopilotLauncher } from './components/CopilotLauncher';
export { default as aiAssistantReducer } from './store/aiAssistantSlice';

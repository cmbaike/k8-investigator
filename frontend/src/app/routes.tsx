import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { Callout } from "@/components/shared/Callout";
import { OverviewPage } from "@/features/dashboard/OverviewPage";
import { DetailPage } from "@/features/investigations/DetailPage";
import { HistoryPage } from "@/features/investigations/HistoryPage";
import { NewInvestigationPage } from "@/features/investigations/NewInvestigationPage";

function NotFound() {
  return <Callout tone="warning" title="Page not found">That page does not exist in this console.</Callout>;
}

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<OverviewPage />} />
        <Route path="investigations" element={<HistoryPage />} />
        <Route path="investigations/new" element={<NewInvestigationPage />} />
        <Route path="investigations/:id" element={<DetailPage />} />
        <Route path="overview" element={<Navigate to="/" replace />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

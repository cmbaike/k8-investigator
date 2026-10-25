import { createContext, useContext, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { endpoints } from "@/api/endpoints";
import type { AccessInfo } from "@/types/api";

interface AccessContextValue {
  access: AccessInfo | undefined;
  isPending: boolean;
  isError: boolean;
}

const AccessContext = createContext<AccessContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const query = useQuery({
    queryKey: ["access"],
    queryFn: () => endpoints.access(),
  });

  return (
    <AccessContext.Provider
      value={{ access: query.data, isPending: query.isPending, isError: query.isError }}
    >
      {children}
    </AccessContext.Provider>
  );
}

export function useAccess(): AccessContextValue {
  const value = useContext(AccessContext);

  if (!value) throw new Error("useAccess must be used inside AuthProvider.");

  return value;
}

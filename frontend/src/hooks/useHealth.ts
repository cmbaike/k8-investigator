import { useQuery } from "@tanstack/react-query";
import { endpoints } from "@/api/endpoints";

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: endpoints.health,
    refetchInterval: 30_000,
    retry: false,
  });
}

import { redirect } from "next/navigation";
import { getSession, isSetupComplete } from "@/lib/auth";

export default async function Home() {
  const setup = await isSetupComplete();
  if (!setup) redirect("/setup");
  const session = await getSession();
  if (!session) redirect("/login");
  redirect("/dashboard");
}

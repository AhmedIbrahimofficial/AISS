import { SignUp } from "@clerk/nextjs";

export default function SignUpPage() {
  return (
    <main className="bg-black min-h-screen flex items-center justify-center px-4 pt-20">
      {/* Background grid */}
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          backgroundImage: `linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
                            linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px)`,
          backgroundSize: "40px 40px",
        }}
      />
      <SignUp />
    </main>
  );
}

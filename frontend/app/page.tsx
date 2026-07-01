import HeroVideo from "./components/HeroVideo";
import HeroContent from "./components/HeroContent";
import HeroSocials from "./components/HeroSocials";
import ProjectSection from "./components/ProjectSection";
import AboutSection from "./components/AboutSection";
import FeaturedVideoSection from "./components/FeaturedVideoSection";
import PhilosophySection from "./components/PhilosophySection";
import ServicesSection from "./components/ServicesSection";

export default function Home() {
  return (
    <main className="bg-black">

      {/* ── Hero — full viewport with video bg ─────────────── */}
      <section className="relative min-h-screen overflow-hidden flex flex-col">
        {/* Background video */}
        <HeroVideo />

        {/* Neon grid overlay — subtle cyber texture */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            backgroundImage: `
              linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
              linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px)
            `,
            backgroundSize: "40px 40px",
            zIndex: 1,
          }}
        />

        {/* Dark gradient at bottom so content is readable */}
        <div
          className="absolute bottom-0 left-0 right-0 h-48 pointer-events-none"
          style={{
            background: "linear-gradient(to top, rgba(0,0,0,0.7), transparent)",
            zIndex: 1,
          }}
        />

        {/* Hero content — sits above video */}
        <div className="relative flex flex-col flex-1 pt-24" style={{ zIndex: 2 }}>
          <HeroContent />
          <HeroSocials />
        </div>
      </section>

      {/* ── Platform overview ───────────────────────────────── */}
      <ProjectSection />

      {/* ── About ───────────────────────────────────────────── */}
      <AboutSection />

      {/* ── Featured video ──────────────────────────────────── */}
      <FeaturedVideoSection />

      {/* ── Philosophy ──────────────────────────────────────── */}
      <PhilosophySection />

      {/* ── Services ────────────────────────────────────────── */}
      <ServicesSection />

    </main>
  );
}

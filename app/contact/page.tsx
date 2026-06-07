"use client";
import { useState } from "react";
import { motion } from "framer-motion";
import { Mail, Globe, ExternalLink, MessageSquare, Send } from "lucide-react";

const CONTACT_ITEMS = [
  { icon: Mail,          label: "Email",   value: "contact@aiss.dev",                        href: "mailto:funandentertainmentwithus@gmail.com" },
  { icon: ExternalLink,  label: "GitHub",  value: "AhmedIbrahimofficial",                    href: "https://github.com/AhmedIbrahimofficial" },
  { icon: Globe,         label: "API Docs",value: "localhost:8000/docs",                      href: "/docs" }
];

export default function ContactPage() {
  const [sent, setSent] = useState(false);
  const [form, setForm] = useState({ name: "", email: "", subject: "", message: "" });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSent(true);
  }

  return (
    <main className="bg-black min-h-screen pt-28 pb-20 px-6">
      <div className="max-w-5xl mx-auto">

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7 }}
          className="mb-16"
        >
          <p className="section-label">Contact</p>
          <h1 className="text-5xl md:text-6xl font-bold text-white leading-tight mb-4">
            Get in touch with<br />
            <span className="text-neon">the AISS team</span>
          </h1>
          <p className="text-white/50 text-lg">
            Have a question, want to report a bug, or explore a collaboration? We respond fast.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">

          {/* Contact info */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.7, delay: 0.1 }}
          >
            <h2 className="text-xl font-semibold text-white mb-6">Reach us directly</h2>
            <div className="space-y-4">
              {CONTACT_ITEMS.map((item, i) => (
                <a
                  key={i}
                  href={item.href}
                  className="cyber-card p-4 flex items-center gap-4 group block"
                >
                  <div className="w-10 h-10 rounded-lg bg-neon/10 border border-neon/20 flex items-center justify-center group-hover:bg-neon/20 transition-colors">
                    <item.icon size={18} className="text-neon" />
                  </div>
                  <div>
                    <p className="text-white/40 text-xs uppercase tracking-widest">{item.label}</p>
                    <p className="text-white text-sm font-medium">{item.value}</p>
                  </div>
                </a>
              ))}
            </div>

            <div className="mt-10 cyber-card p-6">
              <h3 className="text-white font-semibold mb-2">Response time</h3>
              <p className="text-white/50 text-sm leading-relaxed">
                We typically respond within <span className="text-neon">24 hours</span>. For urgent
                security issues, please mark your message as URGENT in the subject line.
              </p>
            </div>
          </motion.div>

          {/* Contact form */}
          <motion.div
            initial={{ opacity: 0, x: 30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.7, delay: 0.2 }}
          >
            {sent ? (
              <div className="cyber-card p-10 text-center flex flex-col items-center justify-center h-full">
                <Send size={40} className="text-neon mb-4" />
                <h3 className="text-white font-bold text-2xl mb-2">Message sent!</h3>
                <p className="text-white/50">We will get back to you within 24 hours.</p>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="cyber-card p-6 space-y-4">
                <h2 className="text-xl font-semibold text-white mb-2">Send a message</h2>

                {[
                  { id: "name",    label: "Name",    type: "text",  placeholder: "Your name" },
                  { id: "email",   label: "Email",   type: "email", placeholder: "you@example.com" },
                  { id: "subject", label: "Subject", type: "text",  placeholder: "What is it about?" },
                ].map((f) => (
                  <div key={f.id}>
                    <label className="text-white/40 text-xs uppercase tracking-widest block mb-1">{f.label}</label>
                    <input
                      type={f.type}
                      placeholder={f.placeholder}
                      value={form[f.id as keyof typeof form]}
                      onChange={(e) => setForm({ ...form, [f.id]: e.target.value })}
                      required
                      className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-white text-sm placeholder:text-white/30 outline-none focus:border-neon/50 transition-colors"
                    />
                  </div>
                ))}

                <div>
                  <label className="text-white/40 text-xs uppercase tracking-widest block mb-1">Message</label>
                  <textarea
                    rows={4}
                    placeholder="Tell us what you need..."
                    value={form.message}
                    onChange={(e) => setForm({ ...form, message: e.target.value })}
                    required
                    className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-white text-sm placeholder:text-white/30 outline-none focus:border-neon/50 transition-colors resize-none"
                  />
                </div>

                <button type="submit" className="btn-neon-solid w-full flex items-center justify-center gap-2">
                  <Send size={16} />
                  Send Message
                </button>
              </form>
            )}
          </motion.div>

        </div>
      </div>
    </main>
  );
}

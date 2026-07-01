"use client";
import { useRef, useEffect } from "react";

const VIDEO_URL =
  "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260405_074625_a81f018a-956b-43fb-9aee-4d1508e30e6a.mp4";

export default function HeroVideo() {
  const videoRef = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    // Fade helpers using rAF
    function fadeTo(
      el: HTMLVideoElement,
      targetOpacity: number,
      durationMs: number,
      onDone?: () => void
    ) {
      const start = performance.now();
      const fromOpacity = parseFloat(el.style.opacity) || 0;

      function step(now: number) {
        const t = Math.min((now - start) / durationMs, 1);
        el.style.opacity = String(fromOpacity + (targetOpacity - fromOpacity) * t);
        if (t < 1) {
          requestAnimationFrame(step);
        } else {
          el.style.opacity = String(targetOpacity);
          onDone?.();
        }
      }
      requestAnimationFrame(step);
    }

    // On canplay: play + fade in
    function handleCanPlay() {
      video!.play().then(() => {
        fadeTo(video!, 1, 500);
      });
    }

    // On timeupdate: fade out near end
    let fadingOut = false;
    function handleTimeUpdate() {
      if (!video) return;
      const remaining = video.duration - video.currentTime;
      if (remaining <= 0.55 && !fadingOut) {
        fadingOut = true;
        fadeTo(video, 0, 500);
      }
    }

    // On ended: reset + play + fade in
    function handleEnded() {
      fadingOut = false;
      video!.style.opacity = "0";
      setTimeout(() => {
        video!.currentTime = 0;
        video!.play().then(() => {
          fadeTo(video!, 1, 500);
        });
      }, 100);
    }

    video.addEventListener("canplay", handleCanPlay);
    video.addEventListener("timeupdate", handleTimeUpdate);
    video.addEventListener("ended", handleEnded);

    return () => {
      video.removeEventListener("canplay", handleCanPlay);
      video.removeEventListener("timeupdate", handleTimeUpdate);
      video.removeEventListener("ended", handleEnded);
    };
  }, []);

  return (
    <video
      ref={videoRef}
      src={VIDEO_URL}
      muted
      autoPlay
      playsInline
      preload="auto"
      className="absolute inset-0 w-full h-full object-cover object-bottom"
      style={{ opacity: 0 }}
    />
  );
}

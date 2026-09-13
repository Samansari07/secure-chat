import { useCallback, useRef, useState } from "react";
import { socket } from "./socket";

const API_BASE = import.meta.env.VITE_SERVER_URL || "http://localhost:4000";

async function getIceServers() {
  try {
    const res = await fetch(`${API_BASE}/ice-servers`);
    const { iceServers } = await res.json();
    return iceServers;
  } catch {
    return [{ urls: "stun:stun.l.google.com:19302" }];
  }
}

export function useCall(myUsername) {
  const [callState, setCallState] = useState("idle");
  const [remoteUser, setRemoteUser] = useState(null);
  const [callType, setCallType] = useState("audio");
  const localStreamRef = useRef(null);
  const pcRef = useRef(null);
  const localVideoRef = useRef(null);
  const remoteVideoRef = useRef(null);
  const pendingOfferRef = useRef(null);

  const cleanup = useCallback(() => {
    pcRef.current?.close();
    pcRef.current = null;
    localStreamRef.current?.getTracks().forEach((t) => t.stop());
    localStreamRef.current = null;
    setCallState("idle");
    setRemoteUser(null);
  }, []);

  const createPeerConnection = useCallback(
    async (targetUser) => {
      const iceServers = await getIceServers();
      const pc = new RTCPeerConnection({ iceServers });
      pc.onicecandidate = (e) => {
        if (e.candidate) socket.emit("call:ice-candidate", { to: targetUser, candidate: e.candidate });
      };
      pc.ontrack = (e) => {
        if (remoteVideoRef.current) remoteVideoRef.current.srcObject = e.streams[0];
      };
      pc.onconnectionstatechange = () => {
        if (pc.connectionState === "connected") setCallState("connected");
        if (["disconnected", "failed", "closed"].includes(pc.connectionState)) cleanup();
      };
      return pc;
    },
    [cleanup]
  );

  const startCall = useCallback(
    async (targetUser, type = "audio") => {
      setCallType(type);
      setRemoteUser(targetUser);
      setCallState("calling");
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: type === "video",
      });
      localStreamRef.current = stream;
      if (localVideoRef.current) localVideoRef.current.srcObject = stream;

      const pc = await createPeerConnection(targetUser);
      stream.getTracks().forEach((track) => pc.addTrack(track, stream));
      pcRef.current = pc;

      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      socket.emit("call:invite", { to: targetUser, from: myUsername, callType: type, offer });
    },
    [createPeerConnection, myUsername]
  );

  const acceptCall = useCallback(async () => {
    const { from, offer, callType: type } = pendingOfferRef.current;
    setCallType(type);
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: true,
      video: type === "video",
    });
    localStreamRef.current = stream;
    if (localVideoRef.current) localVideoRef.current.srcObject = stream;

    const pc = await createPeerConnection(from);
    stream.getTracks().forEach((track) => pc.addTrack(track, stream));
    await pc.setRemoteDescription(offer);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    pcRef.current = pc;
    socket.emit("call:answer", { to: from, answer });
    setCallState("connected");
  }, [createPeerConnection]);

  const rejectCall = useCallback(() => {
    const from = pendingOfferRef.current?.from;
    if (from) socket.emit("call:reject", { to: from });
    setCallState("idle");
    setRemoteUser(null);
  }, []);

  const endCall = useCallback(() => {
    if (remoteUser) socket.emit("call:end", { to: remoteUser });
    cleanup();
  }, [remoteUser, cleanup]);

  const attachListeners = useCallback(() => {
    socket.on("call:incoming", ({ from, callType: type, offer }) => {
      pendingOfferRef.current = { from, offer, callType: type };
      setRemoteUser(from);
      setCallType(type);
      setCallState("ringing");
    });
    socket.on("call:answered", async ({ answer }) => {
      await pcRef.current?.setRemoteDescription(answer);
    });
    socket.on("call:ice-candidate", async ({ candidate }) => {
      try {
        await pcRef.current?.addIceCandidate(candidate);
      } catch {
        /* ignore late candidates */
      }
    });
    socket.on("call:rejected", cleanup);
    socket.on("call:ended", cleanup);
  }, [cleanup]);

  return {
    callState,
    remoteUser,
    callType,
    localVideoRef,
    remoteVideoRef,
    startCall,
    acceptCall,
    rejectCall,
    endCall,
    attachListeners,
  };
      }

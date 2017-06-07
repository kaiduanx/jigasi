/*
 * Jigasi, the JItsi GAteway to SIP.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jitsi.jigasi;

import net.java.sip.communicator.service.protocol.*;
import net.java.sip.communicator.service.protocol.event.*;
import net.java.sip.communicator.service.protocol.media.*;
import net.java.sip.communicator.util.Logger;
import org.jitsi.jigasi.util.*;
import org.jitsi.service.neomedia.*;
import org.jitsi.util.*;
import org.jivesoftware.smack.packet.*;

import java.text.*;
import java.util.*;

/**
 * Class represents gateway session which manages single SIP call instance
 * (outgoing or incoming).
 *
 * @author Pawel Domas
 */
public class GatewaySession
    implements OperationSetJitsiMeetTools.JitsiMeetRequestListener,
               DTMFListener
{
    /**
     * The logger.
     */
    private final static Logger logger = Logger.getLogger(GatewaySession.class);

    /**
     * The name of the room password header to check in headers for a room
     * password to use when joining the Jitsi Meet conference.
     */
    private final String roomPassHeaderName;

    /**
     * Default value of extra INVITE header which specifies password required
     * to enter MUC room that is hosting the Jitsi Meet conference.
     */
    public static final String JITSI_MEET_ROOM_PASS_HEADER_DEFAULT
        = "Jitsi-Conference-Room-Pass";

    /**
     * Name of extra INVITE header which specifies password required to enter
     * MUC room that is hosting the Jitsi Meet conference.
     */
    private static final String JITSI_MEET_ROOM_PASS_HEADER_PROPERTY
        = "JITSI_MEET_ROOM_PASS_HEADER_NAME";

    /**
     * Account property name of custom name for extra INVITE header which
     * specifies name of MUC room that is hosting the Jitsi Meet conference.
     */
    private static final String JITSI_MEET_ROOM_HEADER_PROPERTY
        = "JITSI_MEET_ROOM_HEADER_NAME";

    private static final String COMCAST_DIRECTION_HEADER_NAME
        = "Comcast-Direction";

    private static final String COMCAST_DIRECTION_OUTGOING
        = "outgoing";

    private static final String COMCAST_APP_DOMAIN_HEADER_NAME
        = "Comcast-App-Domain";

    /**
     * The name of the header to search in the INVITE headers for base domain
     * to be used to extract the subdomain from the roomname in order
     * to construct custom bosh URL to enter MUC room that is hosting
     * the Jitsi Meet conference.
     */
    private final String domainBaseHeaderName;

    /**
     * Defult value optional INVITE header which specifies the base domain
     * to be used to extract the subdomain from the roomname in order
     * to construct custom bosh URL to enter MUC room that is hosting
     * the Jitsi Meet conference.
     */
    public static final String JITSI_MEET_DOMAIN_BASE_HEADER_DEFAULT
        = "Jitsi-Conference-Domain-Base";

    /**
     * The account property to use to set custom header name for domain base.
     */
    private static final String JITSI_MEET_DOMAIN_BASE_HEADER_PROPERTY
        = "JITSI_MEET_DOMAIN_BASE_HEADER_NAME";

    /**
     * The <tt>SipGateway</tt> that manages this session.
     */
    private SipGateway sipGateway;

    /**
     * The {@link OperationSetJitsiMeetTools} for SIP leg.
     */
    private final OperationSetJitsiMeetTools jitsiMeetTools;

    /**
     * The <tt>JvbConference</tt> that handles current JVB conference.
     */
    private JvbConference jvbConference;

    /**
     * The SIP call instance if any SIP call is active.
     */
    private Call call;

    /**
     * Stores JVB call instance that will be merged into single conference with
     * SIP call.
     */
    private Call jvbConferenceCall;

    /**
     * Object listens for SIP call state changes.
     */
    private final SipCallStateListener callStateListener
        = new SipCallStateListener();

    /**
     * Peers state listener that publishes peer state in MUC presence status.
     */
    private CallPeerListener peerStateListener;

    /**
     * IF we work in outgoing connection mode then this field contains the SIP
     * number to dial.
     */
    private String destination;

    /**
     * The call context assigned for the current call.
     */
    private CallContext callContext;

    /**
     * SIP protocol provider instance.
     */
    private ProtocolProviderService sipProvider;

    /**
     * FIXME: to be removed ?
     */
    private final Object waitLock = new Object();

    /**
     * FIXME: JVB room name property is not available at the moment when call
     *        is created, because header is not parsed yet
     */
    private WaitForJvbRoomNameThread waitThread;

    /**
     * Gateway session listeners.
     */
    private final ArrayList<GatewaySessionListener> listeners
        = new ArrayList<>();

    /**
     * Global participant count during this session including the focus.
     */
    private int participantsCount = 0;

    /**
     * Creates new <tt>GatewaySession</tt> for given <tt>callResource</tt>
     * and <tt>sipCall</tt>. We already have SIP call instance, so this session
     * can be considered "incoming" SIP session(was created after incoming call
     * had been received).
     *
     * @param gateway the <tt>SipGateway</tt> instance that will control this
     *                session.
     * @param callContext the call context that identifies this session.
     * @param sipCall the incoming SIP call instance which will be handled by
     *                this session.
     */
    public GatewaySession(SipGateway gateway,
                          CallContext callContext,
                          Call       sipCall)
    {
        this(gateway, callContext);
        this.call = sipCall;
    }

    /**
     * Creates new <tt>GatewaySession</tt> that can be used to initiate outgoing
     * SIP gateway session by using
     * {@link #createOutgoingCall()}
     * method.
     *
     * @param gateway the {@link SipGateway} the <tt>SipGateway</tt> instance
     *                that will control this session.
     * @param callContext the call context that identifies this session.
     */
    public GatewaySession(SipGateway gateway, CallContext callContext)
    {
        this.sipGateway = gateway;
        this.callContext = callContext;
        this.sipProvider = gateway.getSipProvider();
        this.jitsiMeetTools
            = sipProvider.getOperationSet(
                    OperationSetJitsiMeetTools.class);

        // check for custom header name for room pass header
        roomPassHeaderName = sipProvider.getAccountID()
            .getAccountPropertyString(
                JITSI_MEET_ROOM_PASS_HEADER_PROPERTY,
                JITSI_MEET_ROOM_PASS_HEADER_DEFAULT);

        // check for custom header name for domain base header
        domainBaseHeaderName = sipProvider.getAccountID()
            .getAccountPropertyString(
                JITSI_MEET_DOMAIN_BASE_HEADER_PROPERTY,
                JITSI_MEET_DOMAIN_BASE_HEADER_DEFAULT);
    }

    /**
     * Returns the call context for the current session.
     * @return the call context for the current session.
     */
    public CallContext getCallContext()
    {
        return callContext;
    }

    private void allCallsEnded()
    {
        CallContext ctx = callContext;

        sipGateway.notifyCallEnded(ctx);

        // clear call context after notifying that session ended as
        // listeners to still be able to check the values from context
        destination = null;
        callContext = null;
    }

    private void cancelWaitThread()
    {
        if (waitThread != null)
        {
            waitThread.cancel();
        }
    }

    /**
     * Starts new outgoing session by dialing given SIP number and joining JVB
     * conference held in given MUC room.
     */
    public void createOutgoingCall()
    {
        if (jvbConference != null)
        {
            throw new IllegalStateException("Conference in progress");
        }

        if (call != null)
        {
            throw new IllegalStateException("SIP call in progress");
        }

        this.destination = callContext.getDestination();
        this.destination = this.destination.split("@")[0];

        jvbConference = new JvbConference(this, callContext);

        jvbConference.start();
    }

    /**
     * Returns the name of the chat room that holds current JVB conference or
     * <tt>null</tt> we're not in any room.
     *
     * @return the name of the chat room that holds current JVB conference or
     *         <tt>null</tt> we're not in any room.
     */
    public String getJvbRoomName()
    {
        return jvbConference != null ? jvbConference.getRoomName() : null;
    }

    public String getJvbRoomNameWithOutHostAddress()
    {
        return jvbConference != null ? jvbConference.getRoomName().split("@")[0] : null;
    }

    /**
     * Returns <tt>ChatRoom</tt> that hosts JVB conference of this session
     * if we're already/still in this room or <tt>null</tt> otherwise.
     */
    public ChatRoom getJvbChatRoom()
    {
        return jvbConference != null ? jvbConference.getJvbRoom() : null;
    }

    /**
     * Returns the instance of SIP call if any is currently in progress.
     * @return the instance of SIP call if any is currently in progress.
     */
    public Call getSipCall()
    {
        return call;
    }

    public void hangUp()
    {
        hangUp(-1, null);
    }

    /**
     * Cancels current session.
     */
    private void hangUp(int reasonCode, String reason)
    {
        cancelWaitThread();

        if (jvbConference != null)
        {
            jvbConference.stop();
        }
        else if (call != null)
        {
            if (reasonCode != -1)
                CallManager.hangupCall(call, reasonCode, reason);
            else
                CallManager.hangupCall(call);
        }
    }

    /**
     * Starts a JvbConference with the call context identifying this session.
     * @param ctx the call context of current session.
     */
    private void joinJvbConference(CallContext ctx)
    {
        cancelWaitThread();

        jvbConference = new JvbConference(this, ctx);

        jvbConference.start();
    }

    /*private void joinSipWithJvbCalls()
    {
        List<Call> calls = new ArrayList<Call>();
        calls.add(call);
        calls.add(jvbConferenceCall);

        CallManager.mergeExistingCalls(
            jvbConferenceCall.getConference(), calls);

        sendPresenceExtension(
            createPresenceExtension(
                SipGatewayExtension.STATE_IN_PROGRESS, null));

        jvbConference.setPresenceStatus(
            SipGatewayExtension.STATE_IN_PROGRESS);
    }*/

    void onConferenceCallInvited(Call incomingCall)
    {
        // Incoming SIP connection mode sets common conference here
        if (destination == null)
        {
            call.setConference(incomingCall.getConference());

            boolean useTranslator = incomingCall.getProtocolProvider()
                .getAccountID().getAccountPropertyBoolean(
                    ProtocolProviderFactory.USE_TRANSLATOR_IN_CONFERENCE,
                    false);
            CallPeer peer = incomingCall.getCallPeers().next();
            // if use translator is enabled add a ssrc rewriter
            if (useTranslator && !addSsrcRewriter(peer))
            {
                peer.addCallPeerListener(new CallPeerAdapter()
                {
                    @Override
                    public void peerStateChanged(CallPeerChangeEvent evt)
                    {
                        CallPeer peer = evt.getSourceCallPeer();
                        CallPeerState peerState = peer.getState();

                        if (CallPeerState.CONNECTED.equals(peerState))
                        {
                            peer.removeCallPeerListener(this);
                            addSsrcRewriter(peer);
                        }
                    }
                });
            }
        }
    }

    /**
     * Method called by <tt>JvbConference</tt> to notify that JVB conference
     * call has started.
     * @param jvbConferenceCall JVB call instance.
     * @return any <tt>Exception</tt> that might occurred during handling of the
     *         event. FIXME: is this still needed ?
     */
    Exception onConferenceCallStarted(Call jvbConferenceCall)
    {
        this.jvbConferenceCall = jvbConferenceCall;

        if (destination == null)
        {
            CallManager.acceptCall(call);
        }
        else
        {
            //sendPresenceExtension(
              //  createPresenceExtension(
                //    SipGatewayExtension.STATE_RINGING, null));

            //if (jvbConference != null)
            //{
              //  jvbConference.setPresenceStatus(
                //    SipGatewayExtension.STATE_RINGING);
            //}

            // Make an outgoing call
            final OperationSetBasicTelephony tele
                = sipProvider.getOperationSet(
                        OperationSetBasicTelephony.class);
            // add listener to detect call creation, and add extra headers
            // before inviting, and remove the listener when job is done
            tele.addCallListener(new CallListener()
            {
                @Override
                public void incomingCallReceived(CallEvent callEvent)
                {}

                @Override
                public void outgoingCallCreated(CallEvent callEvent)
                {
                    String roomName = getJvbRoomName();
                    if(roomName != null)
                    {
                        Call call = callEvent.getSourceCall();
                        call.setData("EXTRA_HEADER_NAME.1",
                            sipProvider.getAccountID()
                                .getAccountPropertyString(
                                    JITSI_MEET_ROOM_HEADER_PROPERTY,
                                    "Jitsi-Conference-Room"));
                        call.setData("EXTRA_HEADER_VALUE.1", roomName);
                        call.setData("EXTRA_HEADER_NAME.2",
                            COMCAST_DIRECTION_HEADER_NAME);
                        call.setData("EXTRA_HEADER_VALUE.2",
                            COMCAST_DIRECTION_OUTGOING);
                        String toRoutingId = callContext.getComcastHeader(
                            CallContext.COMCAST_HEADER_ROUTING_ID);
                        // toRoutingId: toroutingid=+15199543186@iristest.comcast.com
                        logger.info("Routing id: " + toRoutingId);
                        if (toRoutingId != null && toRoutingId.split("@").length > 1)
                        {
                            call.setData("EXTRA_HEADER_NAME.3",
                                COMCAST_APP_DOMAIN_HEADER_NAME);
                            //call.setData("EXTRA_HEADER_VALUE.3",
                            //    toRoutingId.split("@")[1]);
                            String accountAddress = sipGateway.getSipProvider().getAccountID()
                                .getAccountPropertyString(ProtocolProviderFactory.ACCOUNT_ADDRESS);
                            logger.info("AccountAddress: " + accountAddress);
                            call.setData("EXTRA_HEADER_VALUE.3", accountAddress);
                        }
                    }

                    tele.removeCallListener(this);
                }

                @Override
                public void callEnded(CallEvent callEvent)
                {
                    tele.removeCallListener(this);
                }
            });
            try
            {
                logger.info("createCall to destination: " + callContext.getDestination() + ", source: " + callContext.getSource());
                this.call = tele.createCall(callContext.getDestination(), callContext.getSource());

                peerStateListener = new CallPeerListener(this.call);

                // Outgoing SIP connection mode sets common conference object
                // just after the call has been created
                call.setConference(jvbConferenceCall.getConference());

                logger.audit("roomId=" + getJvbRoomNameWithOutHostAddress() +
                    ",routingId=" + callContext.getComcastHeader(CallContext.COMCAST_HEADER_ROUTING_ID) +
                    ",Code=Info,traceId=" + callContext.getTraceId() +
                    ",event=onConferenceCallStarted,message=Created outgoing call,to=" +
                    destination + ",call_details=" + call);

                this.call.addCallChangeListener(callStateListener);

                //FIXME: It might be already in progress or ended ?!
                if (!CallState.CALL_INITIALIZATION.equals(call.getCallState()))
                {
                    callStateListener.handleCallState(call, null);
                }
            }
            catch (OperationFailedException | ParseException e)
            {
                return e;
            }
        }

        return null;
    }

    /**
     * Caled by <tt>JvbConference</tt> to notify that JVB call has ended.
     * @param jvbConference <tt>JvbConference</tt> instance.
     */
    void onJvbConferenceStopped(JvbConference jvbConference,
                                int reasonCode, String reason)
    {
        this.jvbConference = null;

        if (call != null)
        {
            hangUp(reasonCode, reason);
        }
        else
        {
            allCallsEnded();
        }
    }

    private void sendPresenceExtension(PacketExtension extension)
    {
        if (jvbConference != null)
        {
            jvbConference.sendPresenceExtension(extension);
        }
        else
        {
            logger.audit("Code=MAJOR,traceId=" + callContext.getTraceId() +
                ",message=JVB conference unavailable. Failed to send packet extension,packet_extension=" +
                extension.toXML() + ",exception=conference is null");
        }
    }

    private void sipCallEnded()
    {
        if (call == null)
            return;

        logger.info("Sip call ended: " + call.toString());

        call.removeCallChangeListener(callStateListener);

        call = null;

        if (jvbConference != null)
        {
            jvbConference.stop();
        }
        else
        {
            allCallsEnded();
        }
    }

    @Override
    public void onJoinJitsiMeetRequest(
        Call call, String room, Map<String, String> data)
    {
        if (jvbConference == null && this.call == call)
        {
            if (room != null)
            {
                callContext.setRoomName(room);
                callContext.setRoomPassword(data.get(roomPassHeaderName));
                callContext.setDomain(data.get(domainBaseHeaderName));
                callContext.setMucAddressPrefix(sipProvider.getAccountID()
                    .getAccountPropertyString(
                        CallContext.MUC_DOMAIN_PREFIX_PROP, "conference"));

                // set all comcast headers
                callContext.setComcastHeader(CallContext.COMCAST_HEADER_ROUTING_ID,
                    data.get(CallContext.COMCAST_HEADER_ROUTING_ID));
                callContext.setComcastHeader(CallContext.COMCAST_HEADER_ROOT_NODE_ID,
                    data.get(CallContext.COMCAST_HEADER_ROOT_NODE_ID));
                callContext.setComcastHeader(CallContext.COMCAST_HEADER_CHILD_NODE_ID,
                    data.get(CallContext.COMCAST_HEADER_CHILD_NODE_ID));
                callContext.setComcastHeader(CallContext.COMCAST_HEADER_ROOM_TOKEN,
                    data.get(CallContext.COMCAST_HEADER_ROOM_TOKEN));
                callContext.setComcastHeader(CallContext.COMCAST_HEADER_ROOM_TOKEN_EXPIRY_TIME,
                    data.get(CallContext.COMCAST_HEADER_ROOM_TOKEN_EXPIRY_TIME));
                String callId = data.get(CallContext.COMCAST_HEADER_CALL_ID);
                callContext.setComcastHeader(CallContext.COMCAST_HEADER_CALL_ID, callId);
                logger.info("Set trace id for incoming SIP call " + callId);
                callContext.setTraceId(callId);
                joinJvbConference(callContext);
            }
        }
    }

    /**
     * Initializes this instance for incoming call which was passed to the
     * constructor {@link #GatewaySession(SipGateway, CallContext, Call)}.
     */
    void initIncomingCall()
    {
        call.addCallChangeListener(callStateListener);

        peerStateListener = new CallPeerListener(call);

        if (jvbConference != null)
        {
            // Reject incoming call
            CallManager.hangupCall(call);
        }
        else
        {
            waitForRoomName();
        }
    }

    private void waitForRoomName()
    {
        if (waitThread != null)
        {
            throw new IllegalStateException("Wait thread exists");
        }

        waitThread = new WaitForJvbRoomNameThread();

        jitsiMeetTools.addRequestListener(this);

        waitThread.start();
    }

    /**
     * Returns {@link Call} instance for JVB leg of the conference.
     */
    public Call getJvbCall()
    {
        return jvbConferenceCall;
    }

    /**
     * Adds new {@link GatewaySessionListener} on this instance.
     * @param listener adds new {@link GatewaySessionListener} that will receive
     *                 updates from this instance.
     */
    public void addListener(GatewaySessionListener listener)
    {
        synchronized(listeners)
        {
            if (!listeners.contains(listener))
                listeners.add(listener);
        }
    }

    /**
     * Removes {@link GatewaySessionListener} from this instance.
     * @param listener removes {@link GatewaySessionListener} that will  stop
     *                 receiving updates from this instance.
     */
    public void removeListener(GatewaySessionListener listener)
    {
        synchronized(listeners)
        {
            listeners.remove(listener);
        }
    }

    /**
     * Notifies {@link GatewaySessionListener}(if any) that we have just joined
     * the conference room(call is not started yet - just the MUC).
     */
    void notifyJvbRoomJoined()
    {
        // set initial participant count
        participantsCount += getJvbChatRoom().getMembersCount();

        Iterable<GatewaySessionListener> gwListeners;
        synchronized (listeners)
        {
            gwListeners = new ArrayList<>(listeners);
        }

        for (GatewaySessionListener listener : gwListeners)
        {
            listener.onJvbRoomJoined(this);
        }
    }

    /**
     * Notifies {@link GatewaySessionListener} that member just joined
     * the conference room(MUC).
     */
    void notifyMemberJoined(ChatRoomMember member)
    {
        participantsCount++;
    }

    /**
     * Returns the cumulative number of participants that were active during
     * this session including the focus.
     * @return the participants count.
     */
    public int getParticipantsCount()
    {
        return participantsCount;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void toneReceived(DTMFReceivedEvent dtmfReceivedEvent)
    {
        if (dtmfReceivedEvent != null
                && dtmfReceivedEvent.getSource() == jvbConferenceCall)
        {
            OperationSetDTMF opSet
                    = sipProvider.getOperationSet(OperationSetDTMF.class);
            if (opSet != null && dtmfReceivedEvent.getStart() != null)
            {
                if (dtmfReceivedEvent.getStart())
                {
                    try
                    {
                        opSet.startSendingDTMF(
                                peerStateListener.thePeer,
                                dtmfReceivedEvent.getValue());
                    }
                    catch (OperationFailedException ofe)
                    {
                        logger.audit("Code=MINOR,traceId=" + callContext.getTraceId() +
                            ",message=Failed to forward a DTMF tone,exception=" + ofe);
                    }
                }
                else
                {
                    opSet.stopSendingDTMF(peerStateListener.thePeer);
                }
            }
        }
    }

    /**
     * Adds a ssrc rewriter to the peers media stream.
     * @param peer the peer which media streams to manipulate
     * @return true if rewriter was added to peer's media stream.
     */
    private boolean addSsrcRewriter(CallPeer peer)
    {
        if (peer instanceof MediaAwareCallPeer)
        {
            MediaAwareCallPeer peerMedia = (MediaAwareCallPeer) peer;

            CallPeerMediaHandler mediaHandler
                = peerMedia.getMediaHandler();
            if (mediaHandler != null)
            {
                MediaStream stream = mediaHandler.getStream(MediaType.AUDIO);
                if (stream != null)
                {
                    stream.setExternalTransformer(
                        new SsrcRewriter(stream.getLocalSourceID()));
                    return true;
                }
            }
        }

        return false;
    }

    class SipCallStateListener
        implements CallChangeListener
    {

        @Override
        public void callPeerAdded(CallPeerEvent evt) { }

        @Override
        public void callPeerRemoved(CallPeerEvent evt)
        {
            //if (evt.getSourceCall().getCallPeerCount() == 0)
            //  sipCallEnded();
        }

        @Override
        public void callStateChanged(CallChangeEvent evt)
        {
            //logger.info("SIP call " + evt);

            handleCallState(evt.getSourceCall(), evt.getCause());
        }

        void handleCallState(Call call, CallPeerChangeEvent cause)
        {
            // Once call is started notify SIP gateway
            if (call.getCallState() == CallState.CALL_IN_PROGRESS)
            {
                logger.info("Sip call IN_PROGRESS: " + call);
                //sendPresenceExtension(
                  //  createPresenceExtension(
                    //    SipGatewayExtension.STATE_IN_PROGRESS, null));

                //jvbConference.setPresenceStatus(
                  //  SipGatewayExtension.STATE_IN_PROGRESS);

                logger.audit("roomId=" + getJvbRoomNameWithOutHostAddress() +
                    ",routingId=" + callContext.getComcastHeader(CallContext.COMCAST_HEADER_ROUTING_ID) +
                    ",Code=Info,traceId=" + callContext.getTraceId() +
                    ",event=OnHandleCallState,message=SIP call format details,format=" +
                    Util.getFirstPeerMediaFormat(call));
            }
            else if(call.getCallState() == CallState.CALL_ENDED)
            {
                // If we have something to show and we're still in the MUC
                // then we display error reason string and leave the room with
                // 5 sec delay.
                if (cause != null
                    && jvbConference != null && jvbConference.isInTheRoom())
                {
                    // Show reason instead of disconnected
                    if (!StringUtils.isNullOrEmpty(cause.getReasonString()))
                    {
                        peerStateListener.unregister();

                        jvbConference.setPresenceStatus(
                            cause.getReasonString());
                    }

                    // Delay 5 seconds
                    new Thread(new Runnable()
                    {
                        @Override
                        public void run()
                        {
                            try
                            {
                                Thread.sleep(5000);

                                sipCallEnded();
                            }
                            catch (InterruptedException e)
                            {
                                Thread.currentThread().interrupt();
                            }
                        }
                    }).start();
                }
                else
                {
                    sipCallEnded();
                }
            }
        }
    }

    class CallPeerListener
        extends CallPeerAdapter
    {
        CallPeer thePeer;

        CallPeerListener(Call call)
        {
            thePeer = call.getCallPeers().next();
            thePeer.addCallPeerListener(this);
        }

        @Override
        public void peerStateChanged(final CallPeerChangeEvent evt)
        {
            CallPeerState callPeerState = (CallPeerState)evt.getNewValue();
            String stateString = callPeerState.getStateString();

            logger.audit("roomId=" + getJvbRoomNameWithOutHostAddress() +
                ",routingId=" + callContext.getComcastHeader(CallContext.COMCAST_HEADER_ROUTING_ID) +
                ",Code=Info,traceId=" + callContext.getTraceId() +
                ",event=OnPeerStateChange,message=peer state changed,call_resource=" +
                callContext.getCallResource() + ",SIP_peer_state=" + stateString);

            if (jvbConference != null)
                jvbConference.setPresenceStatus(stateString);

            if (CallPeerState.BUSY.equals(callPeerState))
            {
                // Hangup the call with 5 sec delay, so that we can see BUSY
                // status in jitsi-meet
                new Thread(new Runnable()
                {
                    @Override
                    public void run()
                    {
                        try
                        {
                            Thread.sleep(5000);
                        }
                        catch (InterruptedException e)
                        {
                            throw new RuntimeException(e);
                        }
                        CallManager.hangupCall(
                                evt.getSourceCallPeer().getCall());
                    }
                }).start();
            }
        }

        void unregister()
        {
            thePeer.removeCallPeerListener(this);
        }
    }

    /**
     * FIXME: to be removed
     */
    class WaitForJvbRoomNameThread
        extends Thread
    {
        private boolean cancel = false;

        @Override
        public void run()
        {
            synchronized (waitLock)
            {
                try
                {
                    waitLock.wait(1000);

                    if (cancel)
                    {
                        logger.info("Wait thread cancelled");
                        return;
                    }

                    if (getJvbRoomName() == null
                        && !CallState.CALL_ENDED.equals(call.getCallState()))
                    {
                        String defaultRoom
                            = JigasiBundleActivator
                            .getConfigurationService()
                            .getString(
                                SipGateway.P_NAME_DEFAULT_JVB_ROOM);

                        if (defaultRoom != null)
                        {
                            logger.info(
                                "Using default JVB room name property "
                                    + defaultRoom);

                            callContext.setRoomName(defaultRoom);

                            joinJvbConference(callContext);
                        }
                        else
                        {
                            logger.info(
                                "No JVB room name provided in INVITE header");

                            hangUp(
                            OperationSetBasicTelephony.HANGUP_REASON_BUSY_HERE,
                            "No JVB room name provided");
                        }
                    }
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                }
                finally
                {
                    jitsiMeetTools.removeRequestListener(GatewaySession.this);
                }
            }
        }

        void cancel()
        {
            if (Thread.currentThread() == waitThread)
            {
                waitThread = null;
                return;
            }

            synchronized (waitLock)
            {
                cancel = true;
                waitLock.notifyAll();
            }
            try
            {
                waitThread.join();
                waitThread = null;
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
            }
        }
    }
}

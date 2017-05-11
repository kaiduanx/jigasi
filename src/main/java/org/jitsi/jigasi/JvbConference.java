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
import net.java.sip.communicator.service.protocol.jabber.*;
import net.java.sip.communicator.service.protocol.media.*;
import net.java.sip.communicator.util.*;
import net.java.sip.communicator.impl.protocol.jabber.extensions.jitsimeet.*;
import net.java.sip.communicator.impl.protocol.jabber.extensions.MiscPacketExtension;
import net.java.sip.communicator.util.Logger;
import org.jitsi.jigasi.util.*;
import org.jitsi.service.neomedia.*;
import org.jitsi.util.*;
import org.jivesoftware.smack.packet.*;
import org.jivesoftware.smackx.packet.*;
import org.osgi.framework.*;

import java.util.*;

/**
 * Class takes care of handling Jitsi Videobridge conference. Currently it waits
 * for the first XMPP provider service to be registered and uses it to join the
 * conference. Once we've joined the focus sends jingle "session-initiate". Next
 * incoming call is accepted which means that we've joined JVB conference.
 * {@link SipGateway} is notified about this fact and it handles it appropriate.
 *
 * @author Pawel Domas
 */
public class JvbConference
    implements RegistrationStateChangeListener,
               ServiceListener,
               ChatRoomMemberPresenceListener,
               LocalUserChatRoomPresenceListener
{
    /**
     * The logger.
     */
    private final static Logger logger = Logger.getLogger(JvbConference.class);

    /**
     * The name of XMPP feature which states for Jigasi SIP Gateway and can be
     * used to recognize gateway client.
     */
    public static final String SIP_GATEWAY_FEATURE_NAME
        = "http://jitsi.org/protocol/jigasi";

    /**
     * The name of XMPP feature for Jingle/DTMF feature (XEP-0181).
     */
    public static final String DTMF_FEATURE_NAME
            = "urn:xmpp:jingle:dtmf:0";

    /**
     * The name of the property that is used to define whether the SIP user of
     * the incoming/outgoing SIP URI should be used as the XMPP resource or not.
     */
    private static final String P_NAME_USE_SIP_USER_AS_XMPP_RESOURCE
        = "org.jitsi.jigasi.USE_SIP_USER_AS_XMPP_RESOURCE";

    /**
     * Default status of our participant before we get any state from
     * the <tt>CallPeer</tt>.
     */
    private static final String INIT_STATUS_NAME = "Initializing Call";

    /**
     * Adds the features supported by jigasi to a specific
     * <tt>OperationSetJitsiMeetTools</tt> instance.
     */
    private static void addSupportedFeatures(
            OperationSetJitsiMeetTools meetTools)
    {
        meetTools.addSupportedFeature(SIP_GATEWAY_FEATURE_NAME);
        meetTools.addSupportedFeature(DTMF_FEATURE_NAME);

        // Remove ICE support from features list ?
        if (JigasiBundleActivator.getConfigurationService()
                .getBoolean(SipGateway.P_NAME_DISABLE_ICE, false))
        {
            meetTools.removeSupportedFeature(
                    "urn:xmpp:jingle:transports:ice-udp:1");

            logger.info("ICE feature will not be advertised");
        }
    }

    /**
     * {@link GatewaySession} that uses this <tt>JvbConference</tt> instance.
     */
    private final GatewaySession gatewaySession;

    /**
     * The XMPP account used for the call handled by this instance.
     */
    private AccountID xmppAccount;

    /**
     * The XMPP password used for the call handled by this instance.
     */
    private String xmppPassword;

    /**
     * The XMPP provider used to join JVB conference.
     */
    private ProtocolProviderService xmppProvider;

    /**
     * The call context used to create this conference, contains info as
     * room name and room password and other optional parameters.
     */
    private final CallContext callContext;

    /**
     * <tt>ChatRoom</tt> instance that hosts the conference(not null if joined).
     */
    private ChatRoom mucRoom;

    /**
     * Indicates whether this instance has been started.
     */
    private boolean started;

    /**
     * The call established with JVB conference.
     */
    private Call jvbCall;

    /**
     * Operation set telephony.
     */
    private OperationSetBasicTelephony telephony;

    /**
     * Object listens for incoming calls.
     */
    private final JvbCallListener callListener
        = new JvbCallListener();

    /**
     * Object listens for call state changes.
     */
    private final JvbCallChangeListener callChangeListener
        = new JvbCallChangeListener();

    /**
     * <tt>ProtocolProviderFactory</tt> instance used to manage XMPP accounts.
     */
    private ProtocolProviderFactory xmppProviderFactory;

    /**
     * Handles timeout for the waiting for JVB conference call invite sent by
     * the focus.
     */
    private JvbInviteTimeout inviteTimeout = new JvbInviteTimeout();

    /**
     * Call hang up reason string that will be sent to the SIP peer.
     */
    private String endReason;

    /**
     * Call hang up reason code that will be sent to the SIP peer.
     */
    private int endReasonCode;

    /**
     * Address of the focus member that has invited us to the conference.
     * Used to identify the focus user and dispose the session when it leaves
     * the room.
     */
    private String focusResourceAddr;

    /**
     * Creates new instance of <tt>JvbConference</tt>
     * @param gatewaySession the <tt>GatewaySession</tt> that will be using this
     *                       <tt>JvbConference</tt>.
     * @param ctx the call context of the current conference
     */
    public JvbConference(GatewaySession gatewaySession, CallContext ctx)
    {
        this.gatewaySession = gatewaySession;
        this.callContext = ctx;
    }

    /**
     * Includes info about given <tt>peer</tt> media SSRCs in MUC presence.
     * @param peer the <tt>CallPeer</tt> whose media SSRCs will be advertised.
     */
    private void advertisePeerSSRCs(CallPeer peer)
    {
        String audioSSRC = getPeerSSRCforMedia(peer,
                                               MediaType.AUDIO);
        String videoSSRC = getPeerSSRCforMedia(peer,
                                               MediaType.VIDEO);
        logger.info(
            "Peer " + peer.getState()
                + " SSRCs audio: " + audioSSRC
                + " video: " + videoSSRC);

        MediaPresenceExtension mediaPresence
            = new MediaPresenceExtension();

        if (audioSSRC != null)
        {
            MediaPresenceExtension.Source ssrc
                = new MediaPresenceExtension.Source();

            ssrc.setMediaType(MediaType.AUDIO.toString());
            ssrc.setSSRC(audioSSRC);

            mediaPresence.addChildExtension(ssrc);
        }

        if (videoSSRC != null)
        {
            MediaPresenceExtension.Source ssrc
                = new MediaPresenceExtension.Source();

            ssrc.setMediaType(MediaType.VIDEO.toString());
            ssrc.setSSRC(videoSSRC);

            mediaPresence.addChildExtension(ssrc);
        }

        sendPresenceExtension(mediaPresence);
    }

    private String getSipUri()
    {
        String mucDisplayName = null;

        String sipDestination = callContext.getDestination();
        Call sipCall = gatewaySession.getSipCall();

        if (sipDestination != null)
        {
            mucDisplayName = sipDestination;
        }
        else if (sipCall != null)
        {
            CallPeer firstPeer = sipCall.getCallPeers().next();
            if (firstPeer != null)
            {
                mucDisplayName = firstPeer.getDisplayName();
            }
        }

        return mucDisplayName;
    }

    private String getResourceIdentifier()
    {
        String resourceIdentifier = null;
        if (JigasiBundleActivator.getConfigurationService()
            .getBoolean(P_NAME_USE_SIP_USER_AS_XMPP_RESOURCE, false))
        {
            // A SIP address or SIP URI is a Uniform Resource Identifier written
            // in user@domain.tld format (semantically, much like an e-mail
            // address). It addresses a specific telephone extension on a voice
            // over IP system (such as a private branch exchange) or an E.164
            // telephone number dialled through a specific gateway.
            //
            // The SIP and SIPS URI schemes are described in RFC 3261, which
            // defines the Session Initiation Protocol.
            //
            // The XMPP RFC isn't clear as to the syntax of the resource
            // identifier string. It states that a resource identifier MUST be
            // formatted such that the Resourceprep profile of [STRINGPREP] can
            // be applied without failing.
            //
            // Given the above uncertainty, we made the decision to replace
            // anything that is not in the this regex class A-Za-z0-9- with a
            // dash.

            resourceIdentifier = getSipUri();
            if (!StringUtils.isNullOrEmpty(resourceIdentifier))
            {
                int idx = resourceIdentifier.indexOf('@');
                if (idx != -1)
                {
                    // keep only the user part of the SIP URI.
                    resourceIdentifier = resourceIdentifier.substring(0, idx);
                }

                // clean it up for resource usage.
                resourceIdentifier
                    = resourceIdentifier.replace("[^A-Za-z0-9]", "-");
            }
            else
            {
                logger.info("The SIP URI is empty! The XMPP resource " +
                    "identifier will be a random string.");
            }
        }

        if (StringUtils.isNullOrEmpty(resourceIdentifier))
        {
            resourceIdentifier = Util.extractCallIdFromResource(
                callContext.getCallResource());
        }

        return resourceIdentifier;

    }

    /**
     * Returns the <tt>ChatRoom</tt> instance that holds the JVB conference
     * handled by this instance or <tt>null</tt> otherwise.
     */
    public ChatRoom getJvbRoom()
    {
        return mucRoom;
    }

    /**
     * Returns local SSRC of media stream sent towards given <tt>peer</tt>.
     * @param peer the peer to whom media is sent.
     * @param mediaType type of media sent.
     */
    private String getPeerSSRCforMedia(CallPeer peer, MediaType mediaType)
    {
        if (!(peer instanceof MediaAwareCallPeer))
            return null;

        MediaAwareCallPeer peerMedia = (MediaAwareCallPeer) peer;

        CallPeerMediaHandler mediaHandler
            = peerMedia.getMediaHandler();
        if (mediaHandler == null)
            return null;

        MediaStream stream = mediaHandler.getStream(mediaType);
        if (stream == null)
            return null;

        return Long.toString(stream.getLocalSourceID());
    }

    /**
     * Start this JVB conference handler.
     */
    public synchronized void start()
    {
        if (started)
        {
            logger.audit("Code=INFO,traceId=" + callContext.getTraceId() +
                ",message=Already started !");
            return;
        }

        String resourceIdentifier = this.callContext.getComcastHeader(
            CallContext.COMCAST_HEADER_ROUTING_ID);

        this.xmppProviderFactory
            = ProtocolProviderFactory.getProtocolProviderFactory(
                JigasiBundleActivator.osgiContext,
                ProtocolNames.JABBER);

        this.xmppAccount
            = xmppProviderFactory.createAccount(
                    createAccountPropertiesForCallId(
                            callContext,
                            resourceIdentifier));

        xmppProviderFactory.loadAccount(xmppAccount);

        started = true;

        // Look for first XMPP provider
        Collection<ServiceReference<ProtocolProviderService>> providers
            = ServiceUtils.getServiceReferences(
                    JigasiBundleActivator.osgiContext,
                    ProtocolProviderService.class);

        for (ServiceReference<ProtocolProviderService> serviceRef : providers)
        {
            ProtocolProviderService candidate
                = JigasiBundleActivator.osgiContext.getService(serviceRef);

            if (ProtocolNames.JABBER.equals(candidate.getProtocolName()))
            {
                if (candidate.getAccountID()
                    .getAccountUniqueID()
                    .equals(xmppAccount.getAccountUniqueID()))
                {
                    setXmppProvider(candidate);

                    if (this.xmppProvider != null)
                    {
                        break;
                    }
                }
            }
        }

        if (this.xmppProvider == null)
        {
            // Listen for XMPP provider to be added
            JigasiBundleActivator.osgiContext.addServiceListener(this);
        }
    }

    /**
     * Quits current JVB conference if any.
     */
    public synchronized void stop()
    {
        if (!started)
        {
            logger.audit("Code=INFO,traceId=" + callContext.getTraceId() +
                ",message=Already stopped !");
            return;
        }

        logger.audit("Code=INFO,traceId=" + callContext.getTraceId() +
            ",message=Stopping the current JVB conference");
        started = false;

        JigasiBundleActivator.osgiContext.removeServiceListener(this);

        if (telephony != null)
        {
            telephony.removeCallListener(callListener);
            telephony = null;
        }

        if(mucRoom != null)
        {
            leaveConferenceRoom();
        }

        if (jvbCall != null)
        {
            CallManager.hangupCall(jvbCall);
        }

        if (xmppProvider != null)
        {
            xmppProvider.removeRegistrationStateChangeListener(this);

            logger.audit("roomId=" + callContext.getRoomName().split("@")[0] +
                ",Code=Info,routingId=" +
                callContext.getComcastHeader(CallContext.COMCAST_HEADER_ROUTING_ID) +
                ",traceId=" + callContext.getTraceId() +
                ",event=JvbStop,message=Quits current JVB conference. Call resource is removed from xmpp account,call_resource=" +
                callContext.getCallResource() + ",xmpp_account=" + xmppAccount);

            xmppProviderFactory.unloadAccount(xmppAccount);

            xmppProviderFactory = null;

            xmppAccount = null;

            xmppProvider = null;
        }

        gatewaySession.onJvbConferenceStopped(this, endReasonCode, endReason);
    }

    /**
     * Sets XMPP provider that will be used by this instance to join JVB
     * conference. It can be set only once. Once set joining conference process
     * is being started.
     * @param xmppProvider XMPP provider that will be used by this instance to
     *                     join JVB conference.
     */
    private synchronized void setXmppProvider(
            ProtocolProviderService xmppProvider)
    {
        if(this.xmppProvider != null)
            throw new IllegalStateException("unexpected");

        String callResource = callContext.getCallResource();

        if (!xmppProvider.getAccountID().getAccountUniqueID()
                .equals(xmppAccount.getAccountUniqueID()))
        {

            logger.info(
                callResource + " rejects XMPP provider " + xmppProvider);
            return;
        }

        logger.info(callResource + " will use " + xmppProvider);

        this.xmppProvider = xmppProvider;

        xmppProvider.addRegistrationStateChangeListener(this);

        this.telephony
            = xmppProvider.getOperationSet(OperationSetBasicTelephony.class);

        telephony.addCallListener(callListener);

        if (xmppProvider.isRegistered())
        {
            joinConferenceRoom();
        }
        else
        {
            new RegisterThread(xmppProvider, xmppPassword).start();
        }
    }

    @Override
    public synchronized void registrationStateChanged(
            RegistrationStateChangeEvent evt)
    {
        if (started
            && mucRoom == null
            && evt.getNewState() == RegistrationState.REGISTERED)
        {
            // Join the MUC
            joinConferenceRoom();
        }
        else if (evt.getNewState() == RegistrationState.UNREGISTERED)
        {
            logger.audit("Code=WARNING,traceId=" + callContext.getTraceId() +
                ",message=Unregistered XMPP session, call_resource=" +
                callContext.getCallResource());
        }
        else
        {
            logger.audit("roomId=" + callContext.getRoomName().split("@")[0] +
                ",Code=Info,routingId=" +
                callContext.getComcastHeader(CallContext.COMCAST_HEADER_ROUTING_ID) +
                ",traceId=" + callContext.getTraceId() +
                ",event=RequestToRegistrationStateChanged,message=XMPP registration state changed,call_resource=" +
                callContext.getCallResource() + ",event_details=" + evt.toString());
        }
    }

    /**
     * Returns <tt>true</tt> if we are currently in JVB conference room.
     * @return <tt>true</tt> if we are currently in JVB conference room.
     */
    public boolean isInTheRoom()
    {
        return mucRoom != null && mucRoom.isJoined();
    }

    private void joinConferenceRoom()
    {
        // Advertise gateway feature before joining
        addSupportedFeatures(
                xmppProvider.getOperationSet(OperationSetJitsiMeetTools.class));

        OperationSetMultiUserChat muc
            = xmppProvider.getOperationSet(OperationSetMultiUserChat.class);
        muc.addPresenceListener(this);

        try
        {
            String roomName = callContext.getRoomName();
            String roomPassword = callContext.getRoomPassword();

            logger.audit("roomId=" + roomName.split("@")[0] +
                ",routingId=" +
                callContext.getComcastHeader(CallContext.COMCAST_HEADER_ROUTING_ID) +
                ",Code=Info,traceId=" + callContext.getTraceId() +
                ",event=RequestToJoinConferenceRoom,room_name=" + roomName +
                ",message=Joining JVB conference room");

            ChatRoom mucRoom = muc.findRoom(roomName);

            /*
            FIXME: !!!
            if (mucRoom.getMembersCount() == 0)
            {
                logger.error("No focus in the room!");
                stop();
                return;
            }*/

            String resourceIdentifier = getResourceIdentifier();
            String routingId = this.callContext.getComcastHeader(
                CallContext.COMCAST_HEADER_ROUTING_ID);
            if ( !StringUtils.isNullOrEmpty(routingId) ) {
                resourceIdentifier = routingId;
            }
            String childNodeId = this.callContext.getComcastHeader(
                CallContext.COMCAST_HEADER_CHILD_NODE_ID);
            String rootNodeId = this.callContext.getComcastHeader(
                CallContext.COMCAST_HEADER_ROOT_NODE_ID);
            String roomToken = this.callContext.getComcastHeader(
                CallContext.COMCAST_HEADER_ROOM_TOKEN);
            String roomTokenExpiryTime = this.callContext.getComcastHeader(
                CallContext.COMCAST_HEADER_ROOM_TOKEN_EXPIRY_TIME);
            String callId = this.callContext.getComcastHeader(
                CallContext.COMCAST_HEADER_CALL_ID);
            MiscPacketExtension misc = new MiscPacketExtension("connectPSTN",
                callId,
                rootNodeId,
                childNodeId,
                null,
                routingId,
                roomToken,
                roomTokenExpiryTime);

            if (StringUtils.isNullOrEmpty(roomPassword))
            {
                mucRoom.joinAs(resourceIdentifier, null, misc);
            }
            else
            {
                mucRoom.joinAs(resourceIdentifier, roomPassword.getBytes(), misc);
            }

            this.mucRoom = mucRoom;

            mucRoom.addMemberPresenceListener(this);

            String displayName = getSipUri();
            if (displayName != null)
            {
                Nick nick = new Nick(displayName);
                sendPresenceExtension(nick);
            }
            else
            {
                logger.audit("Code=INFO,traceId=" + callContext.getTraceId() +
                    ",message=No display name to use...");
            }

            // Announce that we're connecting to JVB conference
            // (waiting for invite)
            //sendPresenceExtension(
              //  gatewaySession.createPresenceExtension(
                //    SipGatewayExtension.STATE_CONNECTING_JVB, null));

            setPresenceStatus(INIT_STATUS_NAME);

            gatewaySession.notifyJvbRoomJoined();

            inviteTimeout.scheduleTimeout(
                SipGateway.getJvbInviteTimeout());
        }
        catch (Exception e)
        {
            logger.audit("Code=MAJOR,traceId=" + callContext.getTraceId() +
                ",message=Stoping while join to conference room,exception=" + e);

            stop();
        }
    }

    void setPresenceStatus(String statusMsg)
    {
        if (mucRoom != null)
        {
            // Send presence status update
            OperationSetJitsiMeetTools jitsiMeetTools
                = xmppProvider.getOperationSet(
                    OperationSetJitsiMeetTools.class);

            jitsiMeetTools.setPresenceStatus(mucRoom, statusMsg);
        }
    }

    private void onJvbCallEnded()
    {
        if (jvbCall == null)
        {
            logger.audit("Code=INFO,traceId=" + callContext.getTraceId() +
                ",message=Jvb call already disposed");
            return;
        }

        jvbCall.removeCallChangeListener(callChangeListener);

        jvbCall = null;

        if(started)
        {
            stop();
        }
    }

    private void onJvbCallStarted()
    {
        logger.audit("Code=INFO,traceId=" + callContext.getTraceId() +
            ",message=starting JVB conference call is IN_PROGRESS,room_name=" +
            callContext.getRoomName());

        OperationSetIncomingDTMF opSet
            = this.xmppProvider.getOperationSet(OperationSetIncomingDTMF.class);
        if (opSet != null)
            opSet.addDTMFListener(gatewaySession);

        Exception error = gatewaySession.onConferenceCallStarted(jvbCall);

        if (error != null)
        {
            logger.audit("Code=MAJOR,traceId=" + callContext.getTraceId() +
                ",message=Fail to Start JVB conference call,room_name=" +
                callContext.getRoomName() + ",exception=" + error);
        }
    }

    private void leaveConferenceRoom()
    {
        if (mucRoom == null)
        {
            logger.warn("MUC room is null");
            return;
        }

        OperationSetMultiUserChat muc
            = xmppProvider.getOperationSet(OperationSetMultiUserChat.class);
        muc.removePresenceListener(this);

        mucRoom.removeMemberPresenceListener(this);

        mucRoom.leave();

        mucRoom = null;
    }

    @Override
    public void serviceChanged(ServiceEvent serviceEvent)
    {
        if (serviceEvent.getType() != ServiceEvent.REGISTERED)
            return;

        ServiceReference ref = serviceEvent.getServiceReference();

        Object service = JigasiBundleActivator.osgiContext.getService(ref);

        if (!(service instanceof ProtocolProviderService))
            return;

        ProtocolProviderService pps = (ProtocolProviderService) service;

        if (xmppProvider == null &&
            ProtocolNames.JABBER.equals(pps.getProtocolName()))
        {
            setXmppProvider(pps);
        }
    }

    @Override
    public void memberPresenceChanged(ChatRoomMemberPresenceChangeEvent evt)
    {
        logger.info("Member presence change: "+evt);

        String eventType = evt.getEventType();

        if (!ChatRoomMemberPresenceChangeEvent.MEMBER_KICKED.equals(eventType)
            && !ChatRoomMemberPresenceChangeEvent.MEMBER_LEFT.equals(eventType)
            && !ChatRoomMemberPresenceChangeEvent.MEMBER_QUIT.equals(eventType))
        {
            if (ChatRoomMemberPresenceChangeEvent.MEMBER_JOINED
                    .equals(eventType))
            {
                gatewaySession.notifyMemberJoined(evt.getChatRoomMember());
            }

            return;
        }

        ChatRoomMember member = evt.getChatRoomMember();

        logger.audit("roomId=" + callContext.getRoomName().split("@")[0] + ",routingId=" +
            callContext.getComcastHeader(CallContext.COMCAST_HEADER_ROUTING_ID) +
            ",Code=Info,traceId=" + callContext.getTraceId() +
            ",event=OnMemberLeft,member_role=" + member.getRole() +
            ",member_contact_address=" + member.getContactAddress() +
            ",message=Member left");
        // 2 members, us and the focus
        if (member.getContactAddress().equals(focusResourceAddr)
            || evt.getChatRoom().getMembersCount() == 2)
        {
            logger.audit("Code=Info, traceId=" + callContext.getTraceId() +
                (member.getContactAddress().equals(focusResourceAddr) ?
                "Focus" : "Last participant") + " left! - stopping");

            stop();
        }
    }

    /**
     * Handles when user is kicked to stop the conference.
     * @param evt the event
     */
    @Override
    public void localUserPresenceChanged(
        LocalUserChatRoomPresenceChangeEvent evt)
    {

        if (evt.getChatRoom().equals(JvbConference.this.mucRoom)
            && Objects.equals(evt.getEventType(),
                    LocalUserChatRoomPresenceChangeEvent.LOCAL_USER_KICKED))
        {
            this.stop();
        }
    }

    /**
     * Sends given <tt>extension</tt> in MUC presence update packet.
     * @param extension the packet extension to be included in MUC presence.
     */
    void sendPresenceExtension(PacketExtension extension)
    {
        if (mucRoom != null)
        {
            // Send presence update
            OperationSetJitsiMeetTools jitsiMeetTools
                = xmppProvider.getOperationSet(
                    OperationSetJitsiMeetTools.class);

            jitsiMeetTools.sendPresenceExtension(mucRoom, extension);
        }
    }

    /**
     * Returns the name of the chat room that holds JVB conference in which this
     * instance is participating.
     * @return the name of the chat room that holds JVB conference in which this
     * instance is participating.
     */
    public String getRoomName()
    {
        return callContext.getRoomName();
    }

    private class JvbCallListener
        implements CallListener
    {
        @Override
        public void incomingCallReceived(CallEvent event)
        {

            CallPeer focus = event.getSourceCall().getCallPeers().next();
            if (focus == null || focus.getAddress() == null)
            {
                logger.audit("Code=WARNING,traceId=" + callContext.getTraceId() +
                    ",message=Failed to obtain focus peer address");
            }
            else
            {
                String fullAddress = focus.getAddress();
                focusResourceAddr
                    = fullAddress.substring(
                            fullAddress.indexOf("/") + 1);

                logger.audit("roomId=" + callContext.getRoomName().split("@")[0] + ",routingId=" +
                    callContext.getComcastHeader(CallContext.COMCAST_HEADER_ROUTING_ID) +
                    ",Code=Info,traceId=" + callContext.getTraceId() + ",event=OnIncomingCall,from=" +
                    focusResourceAddr + ",message=Got call invite");
            }

            if (jvbCall != null)
            {
                logger.audit("Code=MINOR,traceId=" + callContext.getTraceId() +
                    ",message=JVB conference call already started,hash_code=" +
                    hashCode());
                return;
            }

            if (!started || xmppProvider == null)
            {
                logger.audit("Code=INFO,traceId=" + callContext.getTraceId() +
                    ",message=Instance disposed");
                return;
            }

            inviteTimeout.cancel();

            jvbCall = event.getSourceCall();

            CallPeer peer = jvbCall.getCallPeers().next();
            peer.addCallPeerListener(new CallPeerAdapter()
            {
                @Override
                public void peerStateChanged(CallPeerChangeEvent evt)
                {
                    CallPeer peer = evt.getSourceCallPeer();
                    CallPeerState peerState = peer.getState();
                    logger.audit("Code=INFO,traceId=" + callContext.getTraceId() +
                        ",message=JVB peer state,peer_state=" + peerState +
                        ",call_resource=" + callContext.getCallResource());

                    if (CallPeerState.CONNECTED.equals(peerState))
                    {
                        advertisePeerSSRCs(peer);
                    }
                }
            });

            jvbCall.addCallChangeListener(callChangeListener);

            gatewaySession.onConferenceCallInvited(jvbCall);

            // Accept incoming jingle call
            CallManager.acceptCall(jvbCall);
        }

        @Override
        public void outgoingCallCreated(CallEvent event) { }

        @Override
        public void callEnded(CallEvent event) { }
    }

    private class JvbCallChangeListener
        extends CallChangeAdapter
    {
        @Override
        public synchronized void callStateChanged(CallChangeEvent evt)
        {
            if (jvbCall != evt.getSourceCall())
            {
                logger.audit("Code=WARNING,traceId=" + callContext.getTraceId() +
                    ",message=Call change event for different call ?,event_source_call=" +
                    evt.getSourceCall() + ",jvb_call_details " + jvbCall);
                return;
            }

            // Once call is started notify SIP gateway
            if (jvbCall.getCallState() == CallState.CALL_IN_PROGRESS)
            {
                onJvbCallStarted();
            }
            else if(jvbCall.getCallState() == CallState.CALL_ENDED)
            {
                onJvbCallEnded();
            }
        }
    }

    /**
     * FIXME: temporary
     */
    private Map<String, String> createAccountPropertiesForCallId(
            CallContext ctx,
            String resourceName)
    {
        HashMap<String, String> properties = new HashMap<>();

        String userID = resourceName + "@" + ctx.getDomain();

        properties.put(ProtocolProviderFactory.USER_ID, userID);
        properties.put(ProtocolProviderFactory.SERVER_ADDRESS, ctx.getDomain());
        properties.put(ProtocolProviderFactory.SERVER_PORT, "5222");

        properties.put(ProtocolProviderFactory.RESOURCE, resourceName);
        properties.put(ProtocolProviderFactory.AUTO_GENERATE_RESOURCE, "false");
        properties.put(ProtocolProviderFactory.RESOURCE_PRIORITY, "30");

        // XXX(gp) we rely on the very useful "override" mechanism (see bellow)
        // to "implement" login authentication.
        properties.put(JabberAccountID.ANONYMOUS_AUTH, "true");
        properties.put(ProtocolProviderFactory.IS_CARBON_DISABLED, "true");
        properties.put(ProtocolProviderFactory.DEFAULT_ENCRYPTION, "true");
        properties.put(ProtocolProviderFactory.DEFAULT_SIPZRTP_ATTRIBUTE,
            "false");
        properties.put(ProtocolProviderFactory.IS_USE_ICE, "true");
        properties.put(ProtocolProviderFactory.IS_ACCOUNT_DISABLED, "false");
        properties.put(ProtocolProviderFactory.IS_PREFERRED_PROTOCOL, "false");
        properties.put(ProtocolProviderFactory.IS_SERVER_OVERRIDDEN, "false");
        properties.put(ProtocolProviderFactory.AUTO_DISCOVER_JINGLE_NODES,
            "false");
        properties.put(ProtocolProviderFactory.PROTOCOL, ProtocolNames.JABBER);
        properties.put(ProtocolProviderFactory.IS_USE_UPNP, "false");
        properties.put(ProtocolProviderFactory.USE_DEFAULT_STUN_SERVER, "true");
        properties.put(ProtocolProviderFactory.ENCRYPTION_PROTOCOL
            + ".DTLS-SRTP", "0");
        properties.put(ProtocolProviderFactory.ENCRYPTION_PROTOCOL_STATUS
            + ".DTLS-SRTP", "true");

        String overridePrefix = "org.jitsi.jigasi.xmpp.acc";
        List<String> overriddenProps =
            JigasiBundleActivator.getConfigurationService()
                .getPropertyNamesByPrefix(overridePrefix, false);
        for(String overridenProp : overriddenProps)
        {
            String key = overridenProp.replace(overridePrefix + ".", "");
            String value = JigasiBundleActivator.getConfigurationService()
                .getString(overridenProp);

            // The key for the password field can't end in PASSWORD, otherwise
            // it is encrypted by our configuration service implementation.
            if ("org.jitsi.jigasi.xmpp.acc.PASS".equals(overridenProp))
            {
                // The password is fully managed (i.e. stored/retrieved) by the
                // configuration service and credentials storage service. See
                // the
                //
                //     ProtocolProviderFactory#loadPassword()
                //
                // method. The problem with dynamic XMPP accounts is that they
                // *don't* exist in the configuration, unless we explicitly
                // store them using the
                //
                //     ProtocolProviderFactory#storeAccount()
                //
                // method. Simply loading an account using the
                //
                //     ProtocolProviderFactory#loadAccount()
                //
                // method can't (and doesn't) work, at least not without
                // changing the implementation of the loadAccount method..
                //
                // To avoid to have to store the dynamic accounts in the
                // configuration and, consequently, to have to manage them, to
                // have remove them later, etc. (also NOTE that storing an
                // account WRITES the configuration file), we read the password
                // from a custom key (and *not* from the standard password key,
                // otherwise it gets encrypted by the configuration service, see
                // the comment above) and then we feed it (the password) to the
                // new ServerSecurityAuthority that we create when we register
                // the account. The
                //
                //     ServerSecurityAuthority#obtainCredentials
                //
                // method is called when there no password for a specific
                // account and there we can alter the connection credentials.

                this.xmppPassword = value;
            }
            else if ("org.jitsi.jigasi.xmpp.acc.BOSH_URL_PATTERN"
                        .equals(overridenProp))
            {
                // do not override boshURL with the global setting if
                // we already have a value
                if (StringUtils.isNullOrEmpty(ctx.getBoshURL()))
                    ctx.setBoshURL(value);
            }
            else
            {
                properties.put(key, value);
            }
        }

        String boshUrl = ctx.getBoshURL();
        if (!StringUtils.isNullOrEmpty(boshUrl))
        {
            String roomName = callContext.getRoomName();
            boshUrl = boshUrl.replace(
                "{roomName}",
                // if room name contains @ part, make sure we remove it
                roomName.contains("@") ?
                    Util.extractCallIdFromResource(roomName)
                    : roomName);
            properties.put(JabberAccountID.BOSH_URL, boshUrl);
        }

        // Necessary when doing authenticated XMPP login, otherwise the dynamic
        // accounts get assigned the same ACCOUNT_UID which leads to problems.
        String accountUID = "Jabber:" + userID + "/" + resourceName;
        properties.put(ProtocolProviderFactory.ACCOUNT_UID, accountUID);

        return properties;
    }

    /**
     * Threads handles the timeout for the waiting for conference call invite
     * sent by the focus.
     */
    class JvbInviteTimeout
        implements Runnable
    {
        private final Object syncRoot = new Object();

        private boolean willCauseTimeout = true;

        private long timeout;

        Thread timeoutThread;

        void scheduleTimeout(long timeout)
        {
            synchronized (syncRoot)
            {
                this.timeout = timeout;

                if (timeoutThread != null)
                    throw new IllegalStateException("already scheduled");

                timeoutThread = new Thread(this, "JvbInviteTimeout");

                timeoutThread.start();
            }
        }

        @Override
        public void run()
        {
            synchronized (syncRoot)
            {
                try
                {
                    syncRoot.wait(timeout);

                    if (willCauseTimeout)
                    {
                        logger.audit("Code=MAJOR,traceId=" + callContext.getTraceId() +
                            ",time_out=" + timeout +
                            "ms,message=Did not received session invite within time,exception=Time out");

                        endReason
                            = "No invite from conference focus";
                        endReasonCode
                            = OperationSetBasicTelephony.HANGUP_REASON_TIMEOUT;

                        stop();
                    }
                }
                catch (InterruptedException e)
                {
                    logger.audit("Code=MINOR,traceId=" + callContext.getTraceId() +
                        ",message=Jvb Invite Interrupted,exception=" + e);
                    Thread.currentThread().interrupt();
                }
            }
        }

        void cancel()
        {
            synchronized (syncRoot)
            {
                willCauseTimeout = false;

                if (timeoutThread == null)
                    return;

                syncRoot.notifyAll();
            }

            try
            {
                timeoutThread.join();

                timeoutThread = null;
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
            }
        }
    }
}

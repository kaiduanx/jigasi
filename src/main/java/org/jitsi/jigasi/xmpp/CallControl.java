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
package org.jitsi.jigasi.xmpp;

import net.java.sip.communicator.impl.protocol.jabber.extensions.rayo.RayoIqProvider.*;
import net.java.sip.communicator.util.*;
import net.java.sip.communicator.service.protocol.*;
import org.jitsi.jigasi.*;
import org.jitsi.service.configuration.*;
import org.jivesoftware.smack.packet.*;
import org.jivesoftware.smack.util.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import java.io.StringReader;

/**
 *  Implementation of call control that is capable of utilizing Rayo
 *  XMPP protocol for the purpose of SIP gateway calls management.
 *
 * @author Damian Minkov
 */
public class CallControl
{
    /**
     * The logger.
     */
    private final static Logger logger = Logger.getLogger(CallControl.class);

    /**
     * Name of 'header' attribute that hold JVB room name.
     */
    public static final String ROOM_NAME_HEADER = "JvbRoomName";

    /**
     * Optional header for specifying password required to enter MUC room.
     */
    public static final String ROOM_PASSWORD_HEADER = "JvbRoomPassword";

    /**
     * JID allowed to make outgoing SIP calls.
     */
    public static final String ALLOWED_JID_P_NAME
        = "org.jitsi.jigasi.ALLOWED_JID";

    /**
     * The {@link SipGateway} service which manages gateway sessions.
     */
    private SipGateway gateway;

    /**
     * The only JID that will be allowed to create outgoing SIP calls. If not
     * set then anybody is allowed to do so.
     */
    private String allowedJid;

    /**
     * Constructs new call control instance.
     * @param gateway the sip gateway instance.
     * @param config the config service instance.
     */
    public CallControl(SipGateway gateway, ConfigurationService config)
    {
        this.gateway = gateway;

        Boolean always_trust_mode = config.getBoolean(
            "net.java.sip.communicator.service.gui.ALWAYS_TRUST_MODE_ENABLED",
            false);
        if (always_trust_mode)
        {
            // Always trust mode - prevent failures because there's no GUI
            // to ask the user, but do we always want to trust so, in this
            // mode, the service is vulnerable to Man-In-The-Middle attacks.
            logger.warn(
                "Always trust in remote TLS certificates mode is enabled");
        }

        this.allowedJid = config.getString(ALLOWED_JID_P_NAME, null);

        if (allowedJid != null)
        {
            logger.info("JID allowed to make outgoing calls: " + allowedJid);
        }
    }

    /**
     * Handles an <tt>org.jivesoftware.smack.packet.IQ</tt> stanza of type
     * <tt>set</tt> which represents a request.
     *
     * @param iq the <tt>org.jivesoftware.smack.packet.IQ</tt> stanza of type
     * <tt>set</tt> which represents the request to handle
     * @param ctx the call context to process
     * @return an <tt>org.jivesoftware.smack.packet.IQ</tt> stanza which
     * represents the response to the specified request or <tt>null</tt> to
     * reply with <tt>feature-not-implemented</tt>
     * @throws Exception to reply with <tt>internal-server-error</tt> to the
     * specified request
     */
    public IQ handleIQ(IQ iq, CallContext ctx)
        throws Exception
    {
        try
        {
            String fromBareJid = StringUtils.parseBareAddress(iq.getFrom());
            if (allowedJid != null && !allowedJid.equals(fromBareJid))
            {
                return IQ.createErrorResponse(
                    iq,
                    new XMPPError(XMPPError.Condition.not_allowed));
            }
            else if (allowedJid == null)
            {
                logger.warn("Requests are not secured by JID filter!");
            }

            if (iq instanceof DialIq)
            {
                DialIq dialIq = (DialIq) iq;

                logger.info("DialIQ: " + iq.toXML());
                String from = dialIq.getSource().split("@")[0];
                String to = dialIq.getDestination();
                logger.info("Call context source: " + from + ", destination: " + to);
                ctx.setDestination(to);
                ctx.setSource(from);

                String roomName = dialIq.getHeader(ROOM_NAME_HEADER);
                ctx.setRoomName(roomName);

                String roomPassword = dialIq.getHeader(ROOM_PASSWORD_HEADER);
                ctx.setRoomPassword(roomPassword);
                if (roomName == null)
                    throw new RuntimeException("No JvbRoomName header found");

                // Apply comcast processing, must be done BEFORE ctx.getCallResource
                // because call resource may be reset in comcastProcessing.
                comcastProcess(dialIq, ctx);
                String callResource = ctx.getCallResource();

                gateway.createOutgoingCall(ctx);

                logger.audit("roomId=" + roomName.split("@")[0] +
                    ",routingId=" + ctx.getComcastHeader(CallContext.COMCAST_HEADER_ROUTING_ID) +
                    ",traceId=" + ctx.getTraceId() +
                    ",Code=Info,event=RequestToDial,message=Got dial request,from=" + from +
                    ",to=" + to + ",room_name=" + roomName);

                callResource = "xmpp:" + callResource;

                return RefIq.createResult(iq, callResource);
            }
            else if (iq instanceof HangUp)
            {
                HangUp hangUp = (HangUp) iq;

                String to = hangUp.getTo();
                String callResource = getCallResource(to);
                logger.info("Getting session with callResource: " + callResource);

                GatewaySession session = gateway.getSession(callResource);

                if (session == null)
                    throw new RuntimeException(
                        "No gateway for call: " + callResource);

                session.hangUp();

                return IQ.createResultIQ(iq);
            }
            else
            {
                return null;
            }
        }
        catch (Exception e)
        {
            logger.error(e, e);
            throw e;
        }
    }

    private void comcastProcess(DialIq iq, CallContext callContext)
    {
        if (iq == null || callContext == null)
        {
            return;
        }

        String from = iq.getSource().split("@")[0];
        NodeList eventList;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            InputSource inputSource = new InputSource(new StringReader(iq.toXML()));
            org.w3c.dom.Document document = builder.parse(inputSource);
            eventList = document.getElementsByTagName("data");
        }
        catch (Exception e) 
        {
            return;
        }
        String toRoutingId = "";
        String roomToken = "";
        String roomTokenExpiryTime = "";
        String traceId = "";

        if (eventList != null && eventList.getLength() > 0)
        {
            NamedNodeMap nodeMap = eventList.item(0).getAttributes();
            for (int i = 0; i < nodeMap.getLength(); i++)
            {
                Attr attr = (Attr) nodeMap.item(i);
                String attrName = attr.getNodeName();
                if (attrName.equals("traceid"))
                    traceId = attr.getNodeValue();
                else if (attrName.equals("toroutingid"))
                    toRoutingId = attr.getNodeValue();
                else if (attrName.equals("roomtoken"))
                    roomToken = attr.getNodeValue();
                else if (attrName.equals("roomtokenexpirytime"))
                    roomTokenExpiryTime = attr.getNodeValue();
            }
        }

        if (traceId == null | traceId == "")
            traceId = "-1";
        gateway.getSipProvider().getAccountID().putAccountProperty("traceId", traceId);

        String accountUID = gateway.getSipProvider().getAccountID()
            .getAccountPropertyString(ProtocolProviderFactory.ACCOUNT_UID);

        gateway.getSipProvider().getAccountID().putAccountProperty(
            ProtocolProviderFactory.ACCOUNT_UID, accountUID.replace(
                accountUID.substring(0, accountUID.indexOf("@")), from));
        gateway.getSipProvider().getAccountID().putAccountProperty(
            ProtocolProviderFactory.USER_ID, accountUID.replace(
                accountUID.substring(0, accountUID.indexOf("@")), from));
        gateway.getSipProvider().getAccountID().putAccountProperty(
            ProtocolProviderFactory.AUTHORIZATION_NAME, accountUID.replace(
                accountUID.substring(0, accountUID.indexOf("@")),
                from.substring(from.length() - 10))); // Why 10 ?
        //Dynamic owner/creator
        gateway.getSipProvider().getAccountID().putAccountProperty("fromNumber", from);
        gateway.getSipProvider().getAccountID().putAccountProperty("toroutingid", toRoutingId);
        gateway.getSipProvider().getAccountID().putAccountProperty("roomToken", roomToken);
        gateway.getSipProvider().getAccountID().putAccountProperty("roomTokenExpiryTime", roomTokenExpiryTime);

        callContext.setTraceId(traceId);
        callContext.setComcastHeader(CallContext.COMCAST_HEADER_ROOM_TOKEN, roomToken);
        callContext.setComcastHeader(CallContext.COMCAST_HEADER_ROOM_TOKEN_EXPIRY_TIME, roomTokenExpiryTime);
        callContext.setComcastHeader(CallContext.COMCAST_HEADER_ROUTING_ID, toRoutingId);
        if (toRoutingId != null && !toRoutingId.equals(""))
        {
            callContext.setCustomCallResource(toRoutingId);
        }
    }

    // to looks like
    // 139e10ed-397a-11e7-ad69-fa163e8ed101@st-callcontrol-wbrn-006.poc.sys.comcast.net/+1xxx-xxxxxxx@iristest.comcast.com
    private String getCallResource(String to) 
    {
        if (to == null) 
        {
            return "";
        }
        if (to.contains("/"))
        {
            return to.split("/")[1];
        }
        return "";
    }
}

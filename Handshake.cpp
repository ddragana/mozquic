/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "Logging.h"
#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "NSSHelper.h"
#include "Sender.h"
#include "Streams.h"
#include "sechash.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

namespace mozquic  {

static const uint32_t kMinClientInitial = 1200;
extern std::unordered_map<std::string, uint32_t> mVNHash;

#define HandshakeLog1(...) Log::sDoLog(Log::HANDSHAKE, 1, this, __VA_ARGS__);
#define HandshakeLog2(...) Log::sDoLog(Log::HANDSHAKE, 2, this, __VA_ARGS__);
#define HandshakeLog3(...) Log::sDoLog(Log::HANDSHAKE, 3, this, __VA_ARGS__);
#define HandshakeLog4(...) Log::sDoLog(Log::HANDSHAKE, 4, this, __VA_ARGS__);
#define HandshakeLog5(...) Log::sDoLog(Log::HANDSHAKE, 5, this, __VA_ARGS__);
#define HandshakeLog6(...) Log::sDoLog(Log::HANDSHAKE, 6, this, __VA_ARGS__);
#define HandshakeLog7(...) Log::sDoLog(Log::HANDSHAKE, 7, this, __VA_ARGS__);
#define HandshakeLog8(...) Log::sDoLog(Log::HANDSHAKE, 8, this, __VA_ARGS__);
#define HandshakeLog9(...) Log::sDoLog(Log::HANDSHAKE, 9, this, __VA_ARGS__);
#define HandshakeLog10(...) Log::sDoLog(Log::HANDSHAKE, 10, this, __VA_ARGS__);

void
MozQuic::EncodePN(uint32_t pn, uint8_t *framePtr, size_t &outPNLen)
{
  if (pn >= 128) {
    uint32_t tmp32 = htonl(pn & 0x3fffffff);
    memcpy(framePtr, &tmp32, 4);
    *framePtr = *framePtr | 0xC0; // 4 byte number
    outPNLen = 4;
  } else {
    // 1 byte PN
    *framePtr = pn;
    assert( (*framePtr & 0x80) == 0);
    outPNLen = 1;
  }
}

uint32_t
MozQuic::FlushCrypto(bool forceAck)
{
  assert(mMTU <= kMaxMTU);
  unsigned char pkt[kMaxMTU];
  unsigned char *endpkt = pkt + mMTU;
  unsigned char *framePtr;

  uint32_t used;
  bool sentCrypto;

  for (int i = 0; i < PN_SPACE_01RTT; i++) { // FlushCrypto only send frames that need a long
                                             // packet header. Crypto frames in PN_SPACE_01RTT
                                             // space will be send by StreamState::FlushOnce.

    packetNumberSpace pnSpace = (packetNumberSpace)i;

    if (mStreamState->mConnUnWritten[pnSpace].empty() && !forceAck) {
      continue;
    }
    do {
      used = 0;
      sentCrypto = false;
      unsigned char *lengthPtr = nullptr;
      unsigned char *pnPtr = nullptr;
      size_t pnLen;

      if (CreateLongPacketHeader((pnSpace == PN_SPACE_INITIAL) ? PACKET_TYPE_INITIAL : PACKET_TYPE_HANDSHAKE,
                                 pnSpace, pkt, endpkt - pkt, used, &lengthPtr, &pnPtr, pnLen) != MOZQUIC_OK) {
        return MOZQUIC_ERR_GENERAL;
      }
      assert(used);
      assert(lengthPtr);
      assert(pnPtr);
      framePtr = pkt + used;
      uint32_t usedPacketNumber = mNextTransmitPacketNumber[pnSpace];

      std::unique_ptr<TransmittedPacket> packet(new TransmittedPacket(usedPacketNumber));
      unsigned char *emptyFramePtr = framePtr;
      mStreamState->CreateFrames(framePtr, endpkt - 16,
                                 (pnSpace == PN_SPACE_INITIAL) ? keyPhaseInitial : keyPhaseHandshake,
                                 packet.get()); // last 16 are aead tag
      sentCrypto = (framePtr != emptyFramePtr);
      uint32_t room = endpkt - framePtr - 16; // the last 16 are for aead tag
      if (AckPiggyBack(framePtr, usedPacketNumber, room,
                       (pnSpace == PN_SPACE_INITIAL) ? keyPhaseInitial : keyPhaseHandshake,
                       !sentCrypto, used) == MOZQUIC_OK) {
        if (used) {
          AckLog6("Handy-Ack FlushCrypto packet %lX frame-len=%d\n", usedPacketNumber, used);
        }
        framePtr += used;
      }

      if (framePtr != emptyFramePtr) {
        assert(framePtr > emptyFramePtr);
        //  Check if this is the first Initial packet from the client.
        if (mIsClient && (pnSpace == PN_SPACE_INITIAL) &&
            (packet->mFrameList.begin() != packet->mFrameList.end()) &&
            ((*(packet->mFrameList.begin()))->mType == ReliableData::kCrypto) &&
            !(*(packet->mFrameList.begin()))->mOffset) {
          if (((framePtr - pkt) + 16) < kMinClientInitial) {
            uint32_t paddingNeeded = kMinClientInitial - ((framePtr - pkt) + 16);
            memset (framePtr, 0, paddingNeeded);
            framePtr += paddingNeeded;
          }
        }

        unsigned char cipherPkt[kMozQuicMSS];
        uint32_t cipherLen = 0;
        uint32_t headerLen = emptyFramePtr - pkt;

        // fill in payload length with expected cipherLen
        uint16_t length = (uint16_t)(framePtr - emptyFramePtr) + kTagLen + pnLen;
        length |= 0x4000;
        length = htons(length);
        memcpy(lengthPtr, &length, 2);
        memcpy(cipherPkt, pkt, headerLen);

        assert(mInitialDestCIDForKeys);
        uint32_t rv;

        if (pnSpace == PN_SPACE_INITIAL) {
          rv = mNSSHelper->EncryptInitial(pkt, headerLen, pkt + headerLen, framePtr - emptyFramePtr,
                                          usedPacketNumber,
                                          cipherPkt + headerLen, kMozQuicMSS - headerLen, cipherLen);
        } else {
          rv = mNSSHelper->EncryptHandshake(pkt, headerLen, pkt + headerLen, framePtr - emptyFramePtr,
                                            usedPacketNumber,
                                            cipherPkt + headerLen, kMozQuicMSS - headerLen, cipherLen);
        }
        if (rv != MOZQUIC_OK) {
          HandshakeLog1("TRANSMIT0[%lX] this=%p Encrypt Fail %x\n",
                        usedPacketNumber, this, rv);
          return rv;
        }
        assert (cipherLen == (framePtr - emptyFramePtr) + 16);
        assert(cipherLen < kMaxMTU);
    
        // packet number encryption
        assert(cipherPkt + (pnPtr - pkt) + 4 >= cipherPkt + headerLen); // pn + 4 is in ciphertext
        assert(cipherPkt + (pnPtr - pkt) + 4 <= cipherPkt + headerLen + cipherLen);

        if (pnSpace == PN_SPACE_INITIAL) {
          EncryptPNInPlace(kEncryptInitial, cipherPkt + (pnPtr - pkt),
                           cipherPkt + (pnPtr - pkt) + 4,
                           (cipherPkt + headerLen + cipherLen) - (cipherPkt + (pnPtr - pkt) + 4));
        } else {
          EncryptPNInPlace(kEncryptHandshake, cipherPkt + (pnPtr - pkt),
                           cipherPkt + (pnPtr - pkt) + 4,
                           (cipherPkt + headerLen + cipherLen) - (cipherPkt + (pnPtr - pkt) + 4));
        }

        uint32_t code = mSendState->Transmit(mNextTransmitPacketNumber[pnSpace], !sentCrypto, false,
                                             packet->mQueueOnTransmit,
                                             cipherPkt, cipherLen + headerLen, nullptr);
        if (code != MOZQUIC_OK) {
          HandshakeLog1("TRANSMIT0[%lX] this=%p Transmit Fail %x\n",
                        usedPacketNumber, this, rv);
          return code;
        }
        packet->mTransmitTime = MozQuic::Timestamp();
        packet->mPacketLen = cipherLen + headerLen;
        mStreamState->mUnAckedPackets[pnSpace].push_back(std::move(packet));

        if (sentCrypto) {
          assert(mHighestTransmittedAckable[pnSpace] <= mNextTransmitPacketNumber[pnSpace]);
          mHighestTransmittedAckable[pnSpace] = mNextTransmitPacketNumber[pnSpace];
        }

        Log::sDoLog(Log::HANDSHAKE, 5, this,
                    "TRANSMIT0[%lX] this=%p len=%d total0=%d byte0=%x\n",
                    usedPacketNumber, this, cipherLen + headerLen,
                    mNextTransmitPacketNumber[pnSpace],
                    cipherPkt[0]);

        mNextTransmitPacketNumber[pnSpace]++;

      }
    } while (sentCrypto && !mStreamState->mConnUnWritten[pnSpace].empty());
  }
  return MOZQUIC_OK;
}
uint32_t
MozQuic::ProcessServerStatelessRetry(LongHeaderData &header)
{
  assert(mIsClient);

  HandshakeLog4("server RETRY sets server connID to %s\n",
                header.mSourceCID.Text());
  mDestCIDBeforeRetry = ServerCID();
  mPeerCID = header.mSourceCID;
  mInitialDestCIDForKeys = header.mSourceCID; // We will change the initial destCID
  mRetryCID = header.mSourceCID;
  mToken.reset(new unsigned char[header.mTokenLen]);
  memcpy(mToken.get(), header.mToken.get(), header.mTokenLen);
  mTokenLen = header.mTokenLen;

  mStreamState->mCryptoStream.reset(new CryptoStream(mStreamState.get()));
  mSetupTransportExtension = false;
  mConnectionState = CLIENT_STATE_INITIAL;
  mStreamState->Reset0RTTData();
  mStreamState->mUnAckedPackets[PN_SPACE_INITIAL].clear();
  mStreamState->mConnUnWritten[PN_SPACE_INITIAL].clear();
  SetInitialPacketNumber();
  mNSSHelper.reset(new NSSHelper(this, mTolerateBadALPN, mOriginName.get(), true));

  EnsureSetupClientTransportParameters();

  uint32_t rv = mNSSHelper->DriveHandshake();
  if (rv != MOZQUIC_OK) {
    RaiseError(rv, (char *) "client 1rtt handshake failed\n");
    Shutdown(INTERNAL_ERROR, 0, "\n");
  } else {
    mReceivedServerRetryPkt = true;
  }
  return rv;
}

uint32_t
MozQuic::ProcessVersionNegotiation(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header)
{
  // check packet num and version
  assert(pkt[0] & 0x80);
  assert(header.mVersion == 0);

  unsigned char *framePtr = pkt + header.mHeaderSize;

  if (!mIsClient) {
    HandshakeLog1("VN should only arrive at client. Ignore.\n");
    return MOZQUIC_OK;
  }

  if (mReceivedServerInitialPkt) {
    HandshakeLog1("VN not allowed after server cleartext.\n");
    return MOZQUIC_OK;
  }

  if (mProcessedVN) {
    HandshakeLog1("only handle one VN per session\n");
    return MOZQUIC_OK;
  }

  if (header.mVersion != 0) {
    return MOZQUIC_ERR_VERSION;
  }

  if ((header.mDestCID != mLocalCID) &&
      (!mLocalOmitCID || header.mDestCID.Len())) {
    // this was supposedly copied from client - so this isn't a match
    return MOZQUIC_ERR_VERSION;
  }
  
  uint32_t numVersions = ((pktSize) - header.mHeaderSize) / 4;
  if ((numVersions << 2) != (pktSize - header.mHeaderSize)) {
    RaiseError(MOZQUIC_ERR_VERSION, (char *)"negotiate version packet format incorrect\n");
    return MOZQUIC_ERR_VERSION;
  }

  uint32_t newVersion = 0;
  for (uint16_t i = 0; i < numVersions; i++) {
    uint32_t possibleVersion;
    memcpy((unsigned char *)&possibleVersion, framePtr, 4);
    framePtr += 4;
    possibleVersion = ntohl(possibleVersion);
    // todo this does not give client any preference
    if (mVersion == possibleVersion) {
       HandshakeLog1("Ignore version negotiation packet that offers version "
                     "a client selected.\n");
      return MOZQUIC_OK;
    } else if (!newVersion && VersionOK(possibleVersion)) {
      newVersion = possibleVersion;
    }
  }

  if (newVersion) {
    mVersion = newVersion;
    HandshakeLog2("negotiated version %X\n", mVersion);
    
    std::string key(mOriginName.get());
    auto iter = mVNHash.find(key);
    if (iter != mVNHash.end()) {
      mVNHash.erase(iter);
    }
    mVNHash.insert({key, mVersion});

    mNSSHelper.reset(new NSSHelper(this, mTolerateBadALPN, mOriginName.get(), true));
    mStreamState->mCryptoStream.reset(new CryptoStream(mStreamState.get()));
    mSetupTransportExtension  = false;
    mConnectionState = CLIENT_STATE_INITIAL;
    mStreamState->Reset0RTTData();
    mStreamState->mUnAckedPackets[PN_SPACE_INITIAL].clear();
    EnsureSetupClientTransportParameters();

    uint32_t code = mNSSHelper->DriveHandshake();
    if (code != MOZQUIC_OK) {
      RaiseError(code, (char *) "client 1rtt handshake failed\n");
      return code;
    }

    return MOZQUIC_OK;
  }

  RaiseError(MOZQUIC_ERR_VERSION, (char *)"unable to negotiate version\n");
  return MOZQUIC_ERR_VERSION;
}

uint32_t
MozQuic::ProcessServerInitial(unsigned char *payload, uint32_t payloadSize,
                              LongHeaderData &header, bool &sendAck)
{
  if (header.mVersion != mVersion) {
    HandshakeLog1("wrong version\n");
    Shutdown(VERSION_NEGOTIATION_ERROR, 0, "wrong version\n");
    return MOZQUIC_ERR_GENERAL;
  }

  assert(mLocalCID == ClientCID());

  if ((mLocalCID != header.mDestCID) &&
      (!mLocalOmitCID || header.mDestCID.Len())) {
    HandshakeLog1("wrong connection id\n");
    Shutdown(PROTOCOL_VIOLATION, 0, "wrong connection id\n");
    return MOZQUIC_ERR_GENERAL;
  }

  if (!mReceivedServerInitialPkt) {
    HandshakeLog4("server INITIAL set connID to %s\n", header.mSourceCID.Text());
    mPeerCID = header.mSourceCID;
    mReceivedServerInitialPkt = true;
  }

  // We got a initial packet from the server we do not need the token anymore.
  mTokenLen = 0;
  mToken.reset();

  uint32_t rv = ProcessGeneralDecoded(payload, payloadSize, sendAck, keyPhaseInitial);
  if (rv != MOZQUIC_OK) {
    Shutdown(PROTOCOL_VIOLATION, 0, "handshake decode issue\n");
  }
  return rv;
}

uint32_t
MozQuic::ProcessServerHandshake(const unsigned char *payload, uint32_t payloadSize,
                                LongHeaderData &header, bool &sendAck)
{
  if (header.mVersion != mVersion) {
    HandshakeLog1("wrong version\n");
    Shutdown(VERSION_NEGOTIATION_ERROR, 0, "wrong version\n");
    return MOZQUIC_ERR_GENERAL;
  }

  assert(mLocalCID == ClientCID());

  if ((mLocalCID != header.mDestCID) &&
      (!mLocalOmitCID || header.mDestCID.Len())) {
    HandshakeLog1("wrong connection id\n");
    Shutdown(PROTOCOL_VIOLATION, 0, "wrong connection id\n");
    return MOZQUIC_ERR_GENERAL;
  }

  uint32_t rv = ProcessGeneralDecoded(payload, payloadSize, sendAck, keyPhaseHandshake);
  if (rv != MOZQUIC_OK) {
    Shutdown(PROTOCOL_VIOLATION, 0, "handshake decode issue\n");
  }
  return rv;
}

// Process a client inintial where we do not have any session yet.
uint32_t
MozQuic::ProcessClientFirstInitial(unsigned char *payload, uint32_t payloadSize,
                                   const struct sockaddr *clientAddr,
                                   LongHeaderData &header,
                                   MozQuic **childSession,
                                   bool &sendAck)
{
  HandshakeLog4("client INITIAL first in a session  %s %s\n", header.mSourceCID.Text(), header.mDestCID.Text());
  assert(!mIsChild && !mIsClient);

  *childSession = nullptr;
  if (mConnectionState != SERVER_STATE_LISTEN) {
    return MOZQUIC_ERR_GENERAL;
  }

  mVersion = header.mVersion; // TODO check this.

  MozQuic *child = Accept(clientAddr, header.mSourceCID, header.mDestCID,
                          header.mPacketNumber);
  mChildren.emplace_back(child->mAlive);

  if (mConnEventCB) {
    mConnEventCB(mClosure, MOZQUIC_EVENT_ACCEPT_NEW_CONNECTION, child);
  } else {
    HandshakeLog9("No Event callback\n");
  }
  if (GetForceAddressValidation()) {
    child->mDestCIDBeforeRetry = header.mDestCID;
    // the client will change the initial keys as well and use child->mLocalCID for the new keys.
    child->mInitialDestCIDForKeys = child->mLocalCID;
    child->mRetryCID = child->mLocalCID; // Remember retry CID
    child->SendRetry();
    child->mConnectionState = SERVER_STATE_RETRY;
    // We need to set mDestCIDBeforeRetry if needed before calling EnsureSetupServerTransportExtension.
    child->EnsureSetupServerTransportExtension();
  } else {

    child->mConnectionState = SERVER_STATE_INITIAL;
    child->EnsureSetupServerTransportExtension();
    // TODO if ProcessGeneralDecoded delete the session and do not call callbacks.
    child->ProcessGeneralDecoded(payload, payloadSize, sendAck, keyPhaseInitial);
  }

  *childSession = child;
  return MOZQUIC_OK;
}

uint32_t
MozQuic::ProcessClientInitial(unsigned char *payload, uint32_t payloadSize,
                              LongHeaderData &header,
                              bool &sendAck)
{
  assert(mIsChild && !mIsClient);

  if (header.mVersion != mVersion) {
    HandshakeLog1("wrong version\n");
    Shutdown(VERSION_NEGOTIATION_ERROR, 0, "wrong version\n");
    return MOZQUIC_ERR_GENERAL;
  }

  if (mConnectionState == SERVER_STATE_RETRY) {
    if (!header.mTokenLen) {
      RaiseError(MOZQUIC_ERR_GENERAL, (char *)"No retry token\n");
      Shutdown(PROTOCOL_VIOLATION, 0, "no retry token\n");
      return MOZQUIC_ERR_GENERAL;
    } else {
      if (VerifyToken(header) != MOZQUIC_OK) {
        RaiseError(MOZQUIC_ERR_GENERAL, (char *)"token validation error\n");
        Shutdown(PROTOCOL_VIOLATION, 0, "token validation error\n");
        return MOZQUIC_ERR_GENERAL;
      }
    }
    // Let's make a new CID.
    mParent->mConnectionHash.erase(mLocalCID);
    mLocalCID.Randomize();
    mParent->mConnectionHash.insert( { mLocalCID, this });
    mConnectionState = SERVER_STATE_INITIAL;
  }

  ProcessGeneralDecoded(payload, payloadSize, sendAck,
                        keyPhaseInitial);
  return MOZQUIC_OK;
}

uint32_t
MozQuic::ProcessClientHandshake(unsigned char *payload, uint32_t payloadSize, LongHeaderData &header, bool &sendAck)
{
  assert(mIsChild);
  assert(!mIsClient);

  if (header.mVersion != mVersion) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"version mismatch\n");
    Shutdown(PROTOCOL_VIOLATION, 0, "handshake decode issue\n");
    return MOZQUIC_ERR_GENERAL;
  }

  uint32_t rv = ProcessGeneralDecoded(payload, payloadSize, sendAck, keyPhaseHandshake);
  if (rv != MOZQUIC_OK) {
    Shutdown(PROTOCOL_VIOLATION, 0, "handshake decode issue\n");
  }
  return rv;
}

uint32_t
MozQuic::GenerateVersionNegotiation(LongHeaderData &clientHeader, const struct sockaddr *peer)
{
  assert(!mIsChild);
  assert(!mIsClient);
  assert(mMTU <= kMaxMTU);
  unsigned char pkt[kMaxMTU];
  uint32_t tmp32;

  unsigned char *framePtr = pkt;
  framePtr[0] = 0x80 | (random() & 0xff);
  framePtr++;
  HandshakeLog5("sending a version negotiation packet type =%X\n", pkt[0]);
  // version is 0 to signal VN
  memset(framePtr, 0, 4);
  framePtr += 4;

  CID::FormatLongHeader(clientHeader.mSourceCID, clientHeader.mDestCID, false,
                        framePtr, (pkt + mMTU - sizeof(VersionNegotiationList)) - framePtr, tmp32);
  framePtr += tmp32;

  if (mSabotageVN) {
    // redo the list of version backwards as a test
    HandshakeLog6("Warning generating incorrect version negotation list for testing\n");
    for (int i = (sizeof(VersionNegotiationList) / sizeof(uint32_t)) - 1; i >= 0; i--) {
      tmp32 = htonl(VersionNegotiationList[i]);
      memcpy (framePtr, &tmp32, sizeof(uint32_t));
      framePtr += sizeof(uint32_t);
    }
  } else {
    // normal list of versions
    for (uint32_t i = 0; i < sizeof(VersionNegotiationList) / sizeof(uint32_t); i++) {
      tmp32 = htonl(VersionNegotiationList[i]);
      memcpy (framePtr, &tmp32, sizeof(uint32_t));
      framePtr += sizeof(uint32_t);
    }
  }

  return mSendState->Transmit(clientHeader.mPacketNumber, true, false, false,
                              pkt, framePtr - pkt, peer);
}

uint32_t
MozQuic::SendRetry()
{
  assert(mMTU <= kMaxMTU);
  unsigned char pkt[kMaxMTU];
  unsigned char *endpkt = pkt + mMTU;
  unsigned char *framePtr = pkt;
  uint32_t tmp32;
  uint32_t rv;
  uint32_t used;

  // section 4.1 of transport
  pkt[0] = 0x80 | PACKET_TYPE_RETRY;
  framePtr++;

  tmp32 = htonl(mVersion);
  memcpy(framePtr, &tmp32, 4);
  framePtr += 4;

  rv = CID::FormatLongHeader(mPeerCID, mLocalCID, false,
                             framePtr, endpkt - framePtr, used);
  if (rv != MOZQUIC_OK) return rv;
  framePtr += used;

  // Original Destination CID
  uint8_t odcil = mDestCIDBeforeRetry.Len() ? (mDestCIDBeforeRetry.Len() - 3) : 0;
  assert(odcil < (1 << 4));
  framePtr[0] = odcil;
  framePtr++;
  if (odcil > (endpkt - framePtr)) {
    return MOZQUIC_ERR_GENERAL;
  }
  if (odcil) {
    memcpy(framePtr, mDestCIDBeforeRetry.Data(), mDestCIDBeforeRetry.Len());
  }
  framePtr += mDestCIDBeforeRetry.Len();

  unsigned char sourceAddressInfo[1024];
  uint32_t sourceAddressLen = sizeof(sourceAddressInfo);
  GetPeerAddressHash(mDestCIDBeforeRetry, sourceAddressInfo, &sourceAddressLen);

  HASHContext *hcontext = HASH_Create(HASH_AlgSHA256);
  HASH_Begin(hcontext);
  HASH_Update(hcontext, sourceAddressInfo, sourceAddressLen);
  unsigned int digestLen;
  unsigned char digest[SHA256_LENGTH];
  HASH_End(hcontext, digest, &digestLen, sizeof(digest));
  assert(digestLen == sizeof(digest));

  HandshakeLog5("MakeToken tokenlen=%d\n", digestLen);
  HandshakeLog6("Input : ");
  for (unsigned int i = 0 ; i < sourceAddressLen; i++) {
    HandshakeLog6("%02X ", sourceAddressInfo[i]);
  }
  HandshakeLog6("\nDigest: ");
  for (unsigned int i = 0 ; i < digestLen; i++) {
    HandshakeLog6("%02X ", digest[i]);
  }

  if (digestLen > (endpkt - framePtr)) {
    return MOZQUIC_ERR_GENERAL;
  }
  memcpy(framePtr, digest, digestLen);
  framePtr += digestLen;

  rv = RealTransmit(pkt, framePtr - pkt, nullptr, true);
  if (rv != MOZQUIC_OK) {
    HandshakeLog1("TRANSMIT RETRY packet this=%p Transmit Fail %x\n",
                  this, rv);
    return rv;
  }
  HandshakeLog1("TRANSMIT RETRY packet this=%p Transmitted\n",
                  this);
  return MOZQUIC_OK;
}

uint32_t
MozQuic::VerifyToken(LongHeaderData &header)
{
  unsigned char sourceAddressInfo[1024];
  uint32_t sourceAddressLen = sizeof(sourceAddressInfo);
  GetPeerAddressHash(mDestCIDBeforeRetry,
    sourceAddressInfo, &sourceAddressLen);

  HASHContext *hcontext = HASH_Create(HASH_AlgSHA256);
  HASH_Begin(hcontext);
  HASH_Update(hcontext, sourceAddressInfo, sourceAddressLen);
  unsigned char digest[SHA256_LENGTH];
  unsigned int digestLen;
  HASH_End(hcontext, digest, &digestLen, sizeof(digest));
  assert(digestLen == sizeof(digest));

  HandshakeLog5("MakeToken tokenlen=%d\n", digestLen);
  HandshakeLog6("Input : ");
  for (unsigned int i = 0 ; i < sourceAddressLen; i++) {
    HandshakeLog6("%02X ", sourceAddressInfo[i]);
  }
  HandshakeLog6("\nDigest: ");
  for (unsigned int i = 0 ; i < digestLen; i++) {
    HandshakeLog6("%02X ", digest[i]);
  }

  HandshakeLog6("\nCookie: ");
  for (unsigned int i = 0 ; i < header.mTokenLen; i++) {
    HandshakeLog6("%02X ", header.mToken[i]);
  }

  if (header.mTokenLen != sizeof(digest)) {
    HandshakeLog1("Verify token -  wrong size\n");
    return MOZQUIC_ERR_GENERAL;
  }
  if (memcmp(header.mToken.get(), digest, sizeof(digest))) {
    HandshakeLog1("Verify token -  token wrong\n");
    return MOZQUIC_ERR_GENERAL;
  }
  HandshakeLog1("Token verified!\n");
  return MOZQUIC_OK;
}

}

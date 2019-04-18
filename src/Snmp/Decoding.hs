{-# language BangPatterns #-}
{-# language LambdaCase #-}
{-# language OverloadedStrings #-}

module Snmp.Decoding where

import Data.Bifunctor (first)
import Data.Coerce (coerce)
import Language.Asn.Decoding
import Language.Asn.Types
import Snmp.Types
import qualified Data.Vector as Vector
import qualified Language.Asn.Decoding as AsnDecoding

import Prelude hiding (sequence,null)

trapPdu :: AsnDecoding TrapPdu
trapPdu = sequence $ TrapPdu
  <$> required "enterprise" objectIdentifier
  <*> required "agent-addr"
      ( choice
        [ option "internet" $ tag Application 0 Implicit octetStringWord32
        ]
      )
  <*> required "generic-trap" genericTrap
  <*> required "specific-trap" integer
  <*> required "time-stamp" (tag Application 3 Implicit integer)
  <*> required "variable-bindings" (sequenceOf varBind)

genericTrap :: AsnDecoding GenericTrap
genericTrap = flip mapFailable integer $ \case
  0 -> Right GenericTrapColdStart
  1 -> Right GenericTrapWarmStart
  2 -> Right GenericTrapLinkDown
  3 -> Right GenericTrapLinkUp
  4 -> Right GenericTrapAuthenticationFailure
  5 -> Right GenericTrapEgpNeighborLoss
  6 -> Right GenericTrapEnterpriseSpecific
  _ -> Left "unrecognized generic-trap number"

messageV2 :: AsnDecoding MessageV2
messageV2 = sequence $ MessageV2
  <$  required "version" integer -- make this actually demand that it's 1
  <*> required "community" octetString
  <*> required "data" pdus

simpleSyntax :: AsnDecoding SimpleSyntax
simpleSyntax = choice
  [ fmap SimpleSyntaxInteger $ option "integer-value" int32
  , fmap SimpleSyntaxString $ option "string-value" octetString
  , fmap SimpleSyntaxObjectId $ option "objectID-value" objectIdentifier
  ]

applicationSyntax :: AsnDecoding ApplicationSyntax
applicationSyntax = choice
  [ fmap ApplicationSyntaxIpAddress
      $ option "ipAddress-value" $ tag Application 0 Implicit octetStringWord32
  , fmap ApplicationSyntaxCounter
      $ option "counter-value" $ tag Application 1 Implicit word32
  , fmap ApplicationSyntaxTimeTicks
      $ option "timeticks-value" $ tag Application 3 Implicit word32
  , fmap ApplicationSyntaxArbitrary
      $ option "arbitrary-value" $ tag Application 4 Implicit octetString
  , fmap ApplicationSyntaxBigCounter
      $ option "big-counter-value" $ tag Application 6 Implicit word64
  , fmap ApplicationSyntaxUnsignedInteger
      $ option "unsigned-integer-value" $ tag Application 2 Implicit word32
  ]

objectSyntax :: AsnDecoding ObjectSyntax
objectSyntax = choice
  [ fmap ObjectSyntaxSimple $ option "simple" simpleSyntax
  , fmap ObjectSyntaxApplication $ option "application-wide" applicationSyntax
  ]

bindingResult :: AsnDecoding BindingResult
bindingResult = choice
  [ BindingResultValue <$> option "value" objectSyntax
  , BindingResultUnspecified <$ option "unSpecified" null
  , BindingResultNoSuchObject <$ option "noSuchObject" (tag ContextSpecific 0 Implicit null)
  , BindingResultNoSuchInstance <$ option "noSuchInstance" (tag ContextSpecific 1 Implicit null)
  , BindingResultEndOfMibView <$ option "endOfMibView" (tag ContextSpecific 2 Implicit null)
  ]

varBind :: AsnDecoding VarBind
varBind = sequence $ VarBind
  <$> required "name" objectIdentifier
  -- result is not actually named in the RFC
  <*> required "result" bindingResult

pdu :: AsnDecoding Pdu
pdu = sequence $ Pdu
  <$> required "request-id" (coerce int)
  <*> required "error-status" (coerce integer)
  <*> required "error-index" (coerce int32)
  <*> required "variable-bindings" (fmap Vector.fromList $ sequenceOf varBind)

bulkPdu :: AsnDecoding BulkPdu
bulkPdu = sequence $ BulkPdu
  <$> required "request-id" (coerce int)
  <*> required "non-repeaters" int32
  <*> required "max-repetitions" int32
  <*> required "variable-bindings" (fmap Vector.fromList $ sequenceOf varBind)

pdus :: AsnDecoding Pdus
pdus = choice
  [ PdusGetRequest <$> option "get-request" (tag ContextSpecific 0 Implicit pdu)
  , PdusGetNextRequest <$> option "get-next-request" (tag ContextSpecific 1 Implicit pdu)
  , PdusGetBulkRequest <$> option "get-bulk-request" (tag ContextSpecific 5 Implicit bulkPdu)
  , PdusResponse <$> option "response" (tag ContextSpecific 2 Implicit pdu)
  , PdusSetRequest <$> option "set-request" (tag ContextSpecific 3 Implicit pdu)
  , PdusInformRequest <$> option "inform-request" (tag ContextSpecific 6 Implicit pdu)
    -- This is really silly, but 4 for originally used for traps, and then
    -- they switched it to 7. Realistically, it is necessary to support both.
  , PdusSnmpTrap <$> option "snmpV2-trap" (tag ContextSpecific 4 Implicit trapPdu)
  , PdusSnmpTrap <$> option "snmpV2-trap" (tag ContextSpecific 7 Implicit trapPdu)
  , PdusReport <$> option "report" (tag ContextSpecific 8 Implicit pdu)
  ]

-- onlyMessageId :: AsnDecoding RequestId
-- onlyMessageId = sequence

messageV3 :: AsnDecoding MessageV3
messageV3 = sequence $ MessageV3
  <$  required "msgVersion" integer -- make this actually demand that it's 3
  <*> required "msgGlobalData" headerData
  <*> required "msgSecurityParameters" 
        (mapFailable (first ("while decoding security params" ++) . AsnDecoding.ber usm) octetString)
  <*> required "msgData" scopedPduDataDecoding 

headerData :: AsnDecoding HeaderData
headerData = sequence $ HeaderData
  <$> required "msgID" (coerce int)
  <*> required "msgMaxSize" int32
  <*> required "msgFlags" octetStringWord8
  <*  required "msgSecurityModel" integer -- make sure this is actually 3

-- else Left $ concat
--   [ "wrong auth flags in header data: "
--   , "expected " ++ printf "%08b" (E.cryptoFlags c)
--   , " but found " ++ printf "%08b" w
--   ]

scopedPduDataDecoding :: AsnDecoding ScopedPduData
scopedPduDataDecoding = choice
  [ fmap ScopedPduDataPlaintext $ option "plaintext" scopedPdu
  , fmap ScopedPduDataEncrypted $ option "encryptedPDU" octetString
  ]

scopedPdu :: AsnDecoding ScopedPdu
scopedPdu = sequence $ ScopedPdu
  <$> required "contextEngineID" (coerce octetString)
  <*> required "contextName" octetString
  <*> required "data" pdus

usm :: AsnDecoding Usm -- ((Crypto,Maybe MessageV3),Usm)
usm = sequence $ Usm
  <$> required "msgAuthoritativeEngineID" (coerce octetString)
  <*> required "msgAuthoritativeEngineBoots" int32
  <*> required "msgAuthoritativeEngineTime" int32
  <*> required "msgUserName" octetString
  <*> required "msgAuthenticationParameters" octetString
  <*> required "msgPrivacyParameters" octetString

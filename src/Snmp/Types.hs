{-# language BangPatterns #-}
{-# language LambdaCase   #-}

module Snmp.Types where

import Language.Asn.Types
import Data.Int (Int32)
import Data.Word (Word8,Word32,Word64)
import Data.ByteString (ByteString)
import Data.Vector (Vector)

newtype RequestId = RequestId { getRequestId :: Int }
  deriving (Eq,Ord,Show,Read)
newtype ErrorIndex = ErrorIndex { getErrorIndex :: Int32 }
  deriving (Eq,Show)
newtype ErrorStatus = ErrorStatus { getErrorStatus :: Integer }
  deriving (Eq,Show)

data ObjectSyntax
  = ObjectSyntaxSimple !SimpleSyntax
  | ObjectSyntaxApplication !ApplicationSyntax
  deriving (Eq,Show)

data SimpleSyntax
  = SimpleSyntaxInteger !Int32
  | SimpleSyntaxString !ByteString
  | SimpleSyntaxObjectId !ObjectIdentifier
  deriving (Eq,Show)

data ApplicationSyntax
  = ApplicationSyntaxIpAddress !Word32
  | ApplicationSyntaxCounter !Word32
  | ApplicationSyntaxTimeTicks !Word32
  | ApplicationSyntaxArbitrary !ByteString
  | ApplicationSyntaxBigCounter !Word64
  | ApplicationSyntaxUnsignedInteger !Word32
  deriving (Eq,Show)

data VarBind = VarBind
  { varBindName :: !ObjectIdentifier
  , varBindResult :: !BindingResult
  } deriving (Eq,Show)

data BindingResult
  = BindingResultValue !ObjectSyntax
  | BindingResultUnspecified
  | BindingResultNoSuchObject
  | BindingResultNoSuchInstance
  | BindingResultEndOfMibView
  deriving (Eq,Show)

data Pdus
  = PdusGetRequest !Pdu
  | PdusGetNextRequest !Pdu
  | PdusGetBulkRequest !BulkPdu
  | PdusResponse !Pdu
  | PdusSetRequest !Pdu
  | PdusInformRequest !Pdu
  | PdusSnmpTrap !TrapPdu
  | PdusReport !Pdu
  deriving (Eq,Show)

-- | A message as defined by RFC1157. The @version@ field is omitted
--   since it is required to be 1. The encoding and decoding of 'Message'
--   do have this field present though.
data MessageV2 = MessageV2
  { messageV2CommunityString :: !ByteString
  , messageV2Data :: !Pdus
    -- ^ In the ASN.1 definition of @Message@, this field is an @ANY@.
    --   In practice, it is always @PDUs@.
  } deriving (Eq,Show)

data MessageV3 = MessageV3
  { messageV3GlobalData :: !HeaderData
  , messageV3SecurityParameters :: !Usm
  , messageV3Data :: !ScopedPduData
  } deriving (Eq,Show)

data HeaderData = HeaderData
  { headerDataId :: !RequestId
  , headerDataMaxSize :: !Int32
  , headerDataFlags :: !Word8
  -- The Security Model is omitted because we only
  -- support USM (User Security Model, represented by the number 3),
  -- which seems to be the only one actually in use.
  -- , headerDataSecurityModel :: !Int
  } deriving (Eq,Show)

data AuthType = AuthTypeMd5 | AuthTypeSha
  deriving (Eq,Ord,Show)
data PrivType = PrivTypeDes | PrivTypeAes
  deriving (Eq,Ord,Show)

data Crypto
  = NoAuthNoPriv
  | AuthNoPriv !AuthParameters
  | AuthPriv !AuthParameters !PrivParameters
  deriving (Eq,Show)

data AuthParameters = AuthParameters
  { authParametersType :: !AuthType
  , authParametersKey :: !ByteString
  } deriving (Eq,Show)

data PrivParameters = PrivParameters
  { privParametersType :: !PrivType
  , privParametersKey :: !ByteString
  } deriving (Eq,Show)

newtype AesSalt = AesSalt { getAesSalt :: Word64 }

cryptoFlags :: Crypto -> Word8
cryptoFlags = \case
  NoAuthNoPriv -> 0
  AuthNoPriv _ -> 1
  AuthPriv _ _ -> 3

cryptoAuth :: Crypto -> Maybe AuthParameters
cryptoAuth = \case
  NoAuthNoPriv -> Nothing
  AuthNoPriv a -> Just a
  AuthPriv a _ -> Just a

cryptoPriv :: Crypto -> Maybe PrivParameters
cryptoPriv = \case
  NoAuthNoPriv -> Nothing
  AuthNoPriv _ -> Nothing
  AuthPriv _ a -> Just a

data ScopedPduData
  = ScopedPduDataPlaintext !ScopedPdu
  | ScopedPduDataEncrypted !ByteString
  deriving (Eq,Show)

newtype EngineId = EngineId { getEngineId :: ByteString }
  deriving (Eq,Ord,Show)

data ScopedPdu = ScopedPdu
  { scopedPduContextEngineId :: !EngineId
  , scopedPduContextName :: !ByteString
  , scopedPduData :: !Pdus
  } deriving (Eq,Show)

data Usm = Usm
  { usmAuthoritativeEngineId :: !EngineId
  , usmAuthoritativeEngineBoots :: !Int32
  , usmAuthoritativeEngineTime :: !Int32
  , usmUserName :: !ByteString
  , usmAuthenticationParameters :: !ByteString
  , usmPrivacyParameters :: !ByteString
  } deriving (Eq,Show)

data Pdu = Pdu
  { pduRequestId :: !RequestId
  , pduErrorStatus :: !ErrorStatus
  , pduErrorIndex :: !ErrorIndex
  , pduVariableBindings :: !(Vector VarBind)
  } deriving (Eq,Show)

data BulkPdu = BulkPdu
  { bulkPduRequestId :: !RequestId
  , bulkPduNonRepeaters :: !Int32
  , bulkPduMaxRepetitions :: !Int32
  , bulkPduVariableBindings :: !(Vector VarBind)
  } deriving (Eq,Show)

data TrapPdu = TrapPdu
  { trapPduEnterprise :: !ObjectIdentifier
  , trapPduAgentAddress :: !Word32
  , trapPduGenericTrap :: !GenericTrap
  , trapPduSpecificTrap :: !Integer
  , trapPduTimeStamp :: !Integer
  , trapPduVariableBindings :: [VarBind]
  } deriving (Eq,Show)

data GenericTrap
  = GenericTrapColdStart
  | GenericTrapWarmStart
  | GenericTrapLinkDown
  | GenericTrapLinkUp
  | GenericTrapAuthenticationFailure
  | GenericTrapEgpNeighborLoss
  | GenericTrapEnterpriseSpecific
  deriving (Eq,Show)

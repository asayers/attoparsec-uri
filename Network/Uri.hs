{-# LANGUAGE OverloadedStrings #-}

-- | A module for parsing URIs.
--
-- URIs are parsed as defined in:
--
-- RFC3986: Uniform Resource Identifier (URI): Generic Syntax
-- <http://tools.ietf.org/html/rfc3986>
--
-- and
--
-- RFC6874: Representing IPv6 Zone Identifiers in Address Literals and Uniform
-- Resource Identifiers
-- <http://tools.ietf.org/html/rfc6874>
--
-- This represents the latest definition as of 2nd April 2014.
--
module Network.Uri
       ( -- * Generic URI parser
         Uri(..)
       , Authority(..)
       , UserInfo(..)
       , HostName(..)
       , QueryParam
       , parseUri

         -- * HTTP-specific parser
       , HttpUrl(..)
       , HttpScheme(..)
       , parseHttpUrl

         -- * Parsing utility functions
       , replaceAtClues
       ) where

import Control.Applicative ((<$>), (<*>), (<|>), (<$), optional, many, pure)
import Data.Monoid ((<>))
import Control.Monad       (guard)
import Data.Maybe (fromMaybe)

import qualified Data.Text             as T
import qualified Data.Text.Encoding    as TE
import           Data.Attoparsec.Text  (Parser)
import qualified Data.Attoparsec.Text  as A

import           Network.HTTP.Types.URI (decodePath, queryToQueryText)


--------------------------------------------------------------------------------
-- Types
--------------------------------------------------------------------------------

data Uri = Uri
    { uriScheme      :: T.Text
    , uriAuthority   :: Maybe Authority
    , uriPath        :: T.Text
    , uriQuery       :: [QueryParam]
    , uriFragment    :: Maybe T.Text
    } deriving (Eq, Show)

data Authority = Authority
    { authUserInfo :: Maybe UserInfo
    , authHost        :: HostName
    , authPort        :: Maybe Int
    } deriving (Eq, Show)

data UserInfo = UserInfo
    { _username :: T.Text
    , _password :: Maybe T.Text
    } deriving (Eq, Show)

data HostName = IPv4Address Int Int Int Int
              | IPv6Address Int Int Int Int Int Int Int Int (Maybe T.Text)
              | IPvFuture   Int T.Text
              | DomainName  [T.Text]
              | RegName     T.Text
              deriving (Eq, Show)

type QueryParam = (T.Text, Maybe T.Text)


--------------------------------------------------------------------------------
-- Parsing
--------------------------------------------------------------------------------


-- RFC3986 Section 3: Syntax Components
-- <http://tools.ietf.org/html/rfc3986#section-3>
--
-- The generic URI syntax consists of a hierarchical sequence of components
-- referred to as the scheme, authority, path, query, and fragment.
--
-- URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
--
-- hier-part   = "//" authority path-abempty
--             / path-absolute
--             / path-rootless
--             / path-empty
--
-- The scheme and path components are required, though the path may be empty (no
-- characters).
--
parseUri :: Parser Uri
parseUri = Uri <$> parseScheme               -- scheme ":"
               <*> optional parseAuthority   -- [ "//" authority ]
               <*> parsePath                 -- path
               <*> (parseQuery <|> pure [])  -- [ "?" query ]
               <*> optional parseFragment    -- [ "#" fragment ]

-- RFC3986 Section 3.1: Scheme
-- <http://tools.ietf.org/html/rfc3986#section-3.1>
--
-- Scheme names consist of a sequence of characters beginning with a letter and
-- followed by any combination of letters, digits, plus ("+"), period ("."), or
-- hyphen ("-").  Although schemes are case- insensitive, the canonical form is
-- lowercase and documents that specify schemes must do so with lowercase
-- letters.  An implementation should accept uppercase letters as equivalent to
-- lowercase in scheme names (e.g., allow "HTTP" as well as "http") for the sake
-- of robustness but should only produce lowercase scheme names for consistency.
--
-- scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
--
-- TODO (AS): Consider lower-casing the result
parseScheme :: Parser T.Text
parseScheme = do
    first <- A.satisfy (A.inClass alpha)
    rest  <- A.takeWhile (A.inClass $ alpha ++ digit ++ "-+.")
    A.char ':'
    return $ T.cons first rest


-- RFC3986 Section 3.2: Authority
-- <http://tools.ietf.org/html/rfc3986#section-3.2>
--
-- The authority component is preceded by a double slash ("//") and is
-- terminated by the next slash ("/"), question mark ("?"), or number sign ("#")
-- character, or by the end of the URI.
--
-- authority   = [ userinfo "@" ] host [ ":" port ]
--
parseAuthority :: Parser Authority
parseAuthority = do
    A.string "//"
    Authority <$> optional parseUserInfo
              <*> parseHost
              <*> optional parsePort

-- RFC3986 Section 3.2.1: User Information
-- <http://tools.ietf.org/html/rfc3986#section-3.2.1>
--
-- The userinfo subcomponent may consist of a user name and, optionally,
-- scheme-specific information about how to gain authorization to access the
-- resource.  The user information, if present, is followed by a commercial
-- at-sign ("@") that delimits it from the host.
--
-- userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )
--
-- Use of the format "user:password" in the userinfo field is deprecated.
--
-- TODO (AS): Allow percent-encoded values
parseUserInfo :: Parser UserInfo
parseUserInfo = do
    username <- A.takeWhile (A.inClass $ unreserved ++ subDelims)
    password <- optional $ A.takeWhile (A.inClass $ unreserved ++ subDelims ++ ":")
    A.char '@'
    return $ UserInfo username password

-- RFC3986 Section 3.2.2: Host
-- <http://tools.ietf.org/html/rfc3986#section-3.2.2>
--
-- The host subcomponent of authority is identified by an IP literal
-- encapsulated within square brackets, an IPv4 address in dotted- decimal form,
-- or a registered name.  The host subcomponent is case- insensitive.
--
-- host        = IP-literal / IPv4address / reg-name
--
-- The syntax rule for host is ambiguous because it does not completely
-- distinguish between an IPv4address and a reg-name.  In order to disambiguate
-- the syntax, we apply the "first-match-wins" algorithm: If host matches the
-- rule for IPv4address, then it should be considered an IPv4 address literal
-- and not a reg-name.
--
-- TODO (AS): Consider lower-casing the result. From RFC3986 section 3.2.2:
-- Although host is case-insensitive, producers and normalizers should use
-- lowercase for registered names and hexadecimal addresses for the sake of
-- uniformity, while only using uppercase letters for percent-encodings.
--
parseHost :: Parser HostName
parseHost = parseIPLiteral                   <|>
            parseIPv4Address                 <|>
            DomainName  <$> parseDomainName  <|>
            RegName     <$> parseRegName

-- RFC6874 Section 2: Specification
-- <http://tools.ietf.org/html/rfc6874#section-2>
--
-- A host identified by an Internet Protocol literal address, version 6 or
-- later, is distinguished by enclosing the IP literal within square brackets
-- ("[" and "]").  This is the only place where square bracket characters are
-- allowed in the URI syntax.
--
-- IP-literal = "[" ( IPv6address / IPv6addrz / IPvFuture  ) "]"
--
parseIPLiteral :: Parser HostName
parseIPLiteral = do
    A.char '['
    host <- parseIPv6Address <|> parseIPvFuture
    A.char ']'
    return host

-- RFC6874 Section 3.2.2: Host
-- <http://tools.ietf.org/html/rfc6874#section-3.2.2>
--
-- A host identified by an IPv4 literal address is represented in dotted-decimal
-- notation (a sequence of four decimal numbers in the range 0 to 255, separated
-- by ".").
--
-- IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
--
parseIPv4Address :: Parser HostName
parseIPv4Address =
    IPv4Address <$> decOctet
                <*> (A.char '.' >> decOctet)
                <*> (A.char '.' >> decOctet)
                <*> (A.char '.' >> decOctet)

-- RFC6874 Section 3.2.2: Host
-- <http://tools.ietf.org/html/rfc6874#section-3.2.2>
--
-- A host identified by an IPv6 literal address is represented inside the square
-- brackets without a preceding version flag.  A 128-bit IPv6 address is divided
-- into eight 16-bit pieces.  Each piece is represented numerically in
-- case-insensitive hexadecimal, using one to four hexadecimal digits (leading
-- zeroes are permitted).  The eight encoded pieces are given most-significant
-- first, separated by colon characters.  Optionally, the least-significant two
-- pieces may instead be represented in IPv4 address textual format.  A sequence
-- of one or more consecutive zero-valued 16-bit pieces within the address may
-- be elided, omitting all their digits and leaving exactly two consecutive
-- colons in their place to mark the elision.
--
-- IPv6address =                            6( h16 ":" ) ls32
--             /                       "::" 5( h16 ":" ) ls32
--             / [               h16 ] "::" 4( h16 ":" ) ls32
--             / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
--             / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
--             / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
--             / [ *4( h16 ":" ) h16 ] "::"              ls32
--             / [ *5( h16 ":" ) h16 ] "::"              h16
--             / [ *6( h16 ":" ) h16 ] "::"
--
-- ls32        = ( h16 ":" h16 ) / IPv4address
--             ; least-significant 32 bits of address
--
-- h16         = 1*4HEXDIG
--             ; 16 bits of address represented in hexadecimal
--
-- RFC6874 Section 2: Specification
-- <http://tools.ietf.org/html/rfc6874#section-2>
--
-- ZoneID = 1*( unreserved / pct-encoded )
--
-- IPv6addrz = IPv6address "%25" ZoneID
--
-- TODO (AS): Support percent-encoded characters in zoneId.
--
parseIPv6Address :: Parser HostName
parseIPv6Address =
    IPv6Address <$> mbHexHexadectet
                <*> (A.char ':' >> mbHexHexadectet)
                <*> (A.char ':' >> mbHexHexadectet)
                <*> (A.char ':' >> mbHexHexadectet)
                <*> (A.char ':' >> mbHexHexadectet)
                <*> (A.char ':' >> mbHexHexadectet)
                <*> (A.char ':' >> mbHexHexadectet)
                <*> (A.char ':' >> mbHexHexadectet)
                <*> optional (A.string "%25" >>
                              A.takeWhile1 (A.inClass unreserved))
  where
    -- A hex-encoded number between 0 and 2^16; an empty segment (ie. "::") is
    -- read as 0.
    mbHexHexadectet = hexHexadectet <|> pure 0

-- RFC6874 Section 3.2.2: Host
-- <http://tools.ietf.org/html/rfc6874#section-3.2.2>
--
-- In anticipation of future, as-yet-undefined IP literal address formats, an
-- implementation may use an optional version flag to indicate such a format
-- explicitly rather than rely on heuristic determination.
--
-- The version flag does not indicate the IP version; rather, it indicates
-- future versions of the literal format.  As such, implementations must not
-- provide the version flag for the existing IPv4 and IPv6 literal address forms
-- described below.
--
-- IPvFuture  = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
--
parseIPvFuture :: Parser HostName
parseIPvFuture = do
    A.char 'v' <|> A.char 'V'
    version <- A.hexadecimal
    A.char '.'
    address <- A.takeWhile1 (A.inClass $ unreserved ++ subDelims ++ ":")
    return $ IPvFuture version address

-- RFC6874 Section 3.2.2: Host
-- <http://tools.ietf.org/html/rfc6874#section-3.2.2>
--
-- A registered name intended for lookup in the DNS [...] consists of a sequence
-- of domain labels separated by ".", each domain label starting and ending with
-- an alphanumeric character and possibly also containing "-" characters.  The
-- rightmost domain label of a fully qualified domain name in DNS may be
-- followed by a single "." and should be if it is necessary to distinguish
-- between the complete domain name and some local domain.
--
-- See also: RFC1034 Section 3.5: Preferred name syntax
-- <http://tools.ietf.org/html/rfc1034#section-3.5>
--
parseDomainName :: Parser [T.Text]
parseDomainName = do
    first <- label
    rest  <- many (A.char '.' >> label)
    return (first : rest)
  where
    label = do
        text <- A.takeWhile (A.inClass $ alpha ++ digit ++ "-")
        guard $ not (T.null text)
        guard $ T.head text /= '-'
        guard $ T.last text /= '-'
        return text

-- RFC6874 Section 3.2.2: Host
-- <http://tools.ietf.org/html/rfc6874#section-3.2.2>
--
-- This specification does not mandate a particular registered name
-- lookup technology and therefore does not restrict the syntax of reg-
-- name beyond what is necessary for interoperability.
--
-- reg-name    = *( unreserved / pct-encoded / sub-delims )
--
-- TODO (AS): Allow percent-encoded characters
--
parseRegName :: Parser T.Text
parseRegName = A.takeWhile (A.inClass $ unreserved ++ subDelims)


-- RFC6874 Section 3.2.3: Port
-- <http://tools.ietf.org/html/rfc3986#section-3.2.3>
--
-- The port subcomponent of authority is designated by an optional port number
-- in decimal following the host and delimited from it by a single colon (":")
-- character.
--
-- port        = *DIGIT
--
parsePort :: Parser Int
parsePort = do
    A.char ':'
    A.decimal

-- TODO (AS): Allow '%' only when followed by two hexadecimals
parsePath :: Parser T.Text
parsePath = A.takeWhile isValidInPath
  where
    -- From RFC3986 section 3.3
    -- <http://tools.ietf.org/html/rfc3986#section-3.3>:
    --
    -- pchar       = unreserved / pct-encoded / sub-delims / ":" / "@"
    -- pct-encoded = "%" HEXDIG HEXDIG
    -- unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
    -- sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
    --               / "*" / "+" / "," / ";" / "="
    isValidInPath c = A.inClass "a-zA-Z0-9._~!$&'()*+,;=:@%-" c
                   || A.inClass "/" c

parseQuery :: Parser [QueryParam]
parseQuery = do
    A.char '?'
    first <- parseParam
    rest  <- many (A.satisfy (A.inClass "&;") >> parseParam)
    return (first : rest)
  where
    parseParam = do
        -- FIXME (AS): allowed characters
        key   <- A.takeWhile (A.inClass "A-Za-z0-9")
        value <- optional (A.char '=' >> A.takeWhile (A.inClass "A-Za-z0-9"))
        return (key, value)

parseFragment :: Parser T.Text
parseFragment = do
    A.char '#'
    A.takeWhile (A.inClass "A-Za-z0-9_-")


--------------------------------------------------------------------------------
-- Character classes and auxilary parsers
--------------------------------------------------------------------------------


-- RFC3986 Section 1.3: Syntax Notation
-- <http://tools.ietf.org/html/rfc3986#section-1.3>
--
alpha, digit, hexDig :: String
alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
digit = "0123456789"
hexDig = "ABCDEFabcdef0123456789"

-- RFC3986 Section 2.1: Percent-Encoding
-- <http://tools.ietf.org/html/rfc3986#section-2.1>
--
-- TODO (AS): Figure out how to do this
_pctEncoded :: Parser Int
_pctEncoded = do
    A.char '%'
    charCode <- A.hexadecimal
    guard $ 0 <= charCode && charCode < 256  -- 2 digits of hexadecimal
    return charCode

-- RFC3986 Section 2.2: Reserved Characters
-- <http://tools.ietf.org/html/rfc3986#section-2.2>
--
genDelims, subDelims, reserved :: String
genDelims = ":/?#[]@"
subDelims  = "!$&'()*+,;="
reserved = genDelims ++ subDelims

-- RFC3986 Section 2.3: Unreserved Characters
-- <http://tools.ietf.org/html/rfc3986#section-2.3>
--
unreserved :: String
unreserved  = alpha ++ digit ++ "-._~"

-- RFC6874 Section 3.2.2: Host
-- <http://tools.ietf.org/html/rfc6874#section-3.2.2>
--
-- dec-octet   = DIGIT                 ; 0-9
--             / %x31-39 DIGIT         ; 10-99
--             / "1" 2DIGIT            ; 100-199
--             / "2" %x30-34 DIGIT     ; 200-249
--             / "25" %x30-35          ; 250-255
--
decOctet :: Parser Int
decOctet = do
    x <- A.decimal
    guard $ 0 <= x && x < 256
    return x

-- RFC6874 Section 3.2.2: Host
-- <http://tools.ietf.org/html/rfc6874#section-3.2.2>
--
-- h16         = 1*4HEXDIG ; 16 bits of address represented in hexadecimal
--
hexHexadectet :: Parser Int
hexHexadectet = do
    x <- A.hexadecimal
    guard $ 0 <= x && x < 65536  -- 4 digits of hexadecimal
    return x


--------------------------------------------------------------------------------
-- An HTTP-specialised parser
--------------------------------------------------------------------------------

data HttpUrl = HttpUrl
    { httpUrlScheme      :: HttpScheme
    , httpUrlAuthority   :: Authority
    , httpUrlPath        :: T.Text
    , httpUrlQuery       :: [QueryParam]
    , httpUrlFragment    :: Maybe T.Text
    } deriving (Eq, Show)

data HttpScheme = Http
                | Https
                deriving (Eq, Show)

parseHttpUrl :: Parser HttpUrl
parseHttpUrl = do
    scheme <- (Http  <$ A.asciiCI "http:") <|>
              (Https <$ A.asciiCI "https:")
    authority <- parseAuthority
    path      <- parsePath
    query     <- parseQuery <|> pure []
    let fragment = Nothing

    return $ HttpUrl scheme authority path query fragment


--------------------------------------------------------------------------------
-- Pretty printing
--------------------------------------------------------------------------------

-- prettyPrintHttpUrl :: HttpUrl -> T.Text
-- prettyPrintHttpUrl (HttpUrl scheme authority path queryParams fragment) =
    -- prettyPrintHttpScheme scheme <>
    -- prettyPrintAuthority authority <>
    -- path <>
    -- prettyPrintQueryParams queryParams <>
    -- mbem (prettyPrintFragment <$> fragment)

-- prettyPrintHttpScheme :: HttpScheme -> T.Text
-- prettyPrintHttpScheme scheme = case scheme of
    -- Http  -> "http://"
    -- Https -> "https://"

-- prettyPrintAuthority :: Authority -> T.Text
-- prettyPrintAuthority (Authority mbUserInfo host mbPort) =
    -- mbem (prettyPrintUserInfo <$> mbUserInfo) <>
    -- prettyPrintHostName host <>
    -- mbem (T.cons ':' . T.pack . show <$> mbPort)

-- prettyPrintUserInfo :: UserInfo -> T.Text
-- prettyPrintUserInfo (UserInfo username mbPassword) =
    -- username <> mbem (T.cons ':' <$> mbPassword) `T.snoc` '@'

-- prettyPrintHostName :: HostName -> T.Text
-- prettyPrintHostName hostName = case hostName of
    -- IPv4Address (w, x, y, z) -> T.intercalate "." $ map (T.pack . show) [w,x,y,z]
    -- IPv6Address text         -> text
    -- DomainName labels        -> T.intercalate "." labels

-- prettyPrintQueryParams :: [QueryParam] -> T.Text
-- prettyPrintQueryParams params = case params of
    -- [] -> T.empty
    -- _  -> T.cons '?' $ T.intercalate "&" (map prettyPrintQueryParam params)
  -- where
    -- prettyPrintQueryParam (key, mbValue) =
        -- maybe key (T.snoc key '=' <>) mbValue

-- prettyPrintFragment :: T.Text -> T.Text
-- prettyPrintFragment fragment = T.cons '#' fragment

-- mbem = fromMaybe T.empty

--------------------------------------------------------------------------------
-- Utilitites
--------------------------------------------------------------------------------

-- | Takes a list of predicates and a value, and returns true if any of the
-- predicates hold of it.
any' :: [a -> Bool] -> a -> Bool
any' fs x = any ($ x) fs

-- | Search for instances of 'clue' within 'text'. When a clue is found, begin
-- parsing with 'parser'. If parsing succeeds, replace the parsed text with the
-- result; otherwise, leave the text alone and continue looking for clues.
--
-- This function is for when you have an expensive parser and need to search a
-- large block of text for matching substrings. If the parser always begins with
-- a concrete string, we can effiently search for that string and only run the
-- parser at places in the text block where it's likely to succeed.
--
-- A motivating use-case is searching for urls in a large block of text. Here,
-- we just use @replaceAtClues "http" urlParser text@.
--
-- >>> replaceAtClues "foo" ("foo" .*> decimal) "blah blah foo40 blah foo blah blah foo3 blah"
-- [Left "blah blah ", Right 40, Left " blah foo blah blah ", Right 3, " blah"]
replaceAtClues :: T.Text -> Parser a -> T.Text -> [Either T.Text a]
replaceAtClues clue parser text = reverse $ go [] parser text
  where
    go :: [Either T.Text a] -> Parser a -> T.Text -> [Either T.Text a]
    go processed parser' unprocessed =
        case T.breakOn clue unprocessed of
            (before, "")           ->
                -- No more clues. Add the remainder to the accumulator and
                -- return it.
                addToAccumulator processed before
            (before, linkAndAfter) ->
                -- Found a clue! Attempt to parse, starting with the clue.
                case parseOnly' parser' linkAndAfter of
                    Left _ ->
                        -- It was a red herring; never mind. Move the clue into
                        -- the accumulator and start again on the remainder.
                        let unprocessed' = T.drop (T.length clue) linkAndAfter
                            processed'   = addToAccumulator processed
                                               (T.append before clue)
                        in go processed' parser' unprocessed'
                    Right (leftOver, value) ->
                        -- Jackpot! Add the parsed value to the accumulator and
                        -- start again on the remainder.
                        let unprocessed' = leftOver
                            processed'   = Right value : addToAccumulator
                                               processed before
                        in go processed' parser' unprocessed'

    addToAccumulator :: [Either T.Text a] -> T.Text -> [Either T.Text a]
    addToAccumulator acc val = case (acc, val) of
        (Left accText : rest, valText) ->
            (Left $ T.append accText valText) : rest
        (_, _) -> Left val : acc

-- | Parse 'text' using 'parser', without the option of providing more
-- input. Differs from 'parseOnly' in that it returns the unparsed text on
-- success.
parseOnly' :: Parser a -> T.Text -> Either String (T.Text, a)
parseOnly' parser text = go $ A.parse parser text
  where
    go result = case result of
        A.Fail _ _ errorMsg   -> Left errorMsg
        A.Partial f           -> go (f "")
        A.Done leftOver value -> Right (leftOver, value)


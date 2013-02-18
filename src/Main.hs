{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}

module Main where

import           Control.Applicative
import           Codec.Archive.Tar (Entry,EntryContent(..))
import qualified Codec.Archive.Tar as Tar
import qualified Codec.Archive.Tar.Entry as Tar
import qualified Codec.Archive.Tar.Check as Tar
import qualified Codec.Compression.GZip as Gzip
import           Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as S
import           Data.ByteString.Char8()
import qualified Codec.Digest.SHA as Sha2
import qualified Data.Map as Map
import           Data.List
import           Data.Serialize
import           Data.String
import           System.Directory
import           System.Environment
import           System.FilePath
import qualified System.FilePath.Posix as Posix
import           System.IO
import           System.Process

{-

I'm using this shell command as rough, preliminary specification for the
manifest format:

   tar zxvf $ARCHIVE | grep -v ^[^/]*/metadata/  | xargs sha256sum | sort

However,  this shell command does not work properly with archives that contain
files with spaces in their names,  whereas cabal-sign does.   And this shell
command does produce a few extraneous, harmless errors on directories comprising
the archive.

Currently, this program prohibits empty directories,  which tar tends to omit
anyway.    If this turns out to be an unreasonable assumption,  we will probably
need to include empty directories in the manifest as well.   Also,  block devices
and other object types are prohibited.

Right now the manifest stakes a claim to the names and contents of all files
in any subdirectory of the archive.   It purposely does not stake a claim
to either the compressed encoding,  nor the order the files appear in the
archive.

I'm not yet sure whether or not the manifest should stake a claim on the
additional metadata of the tar archive,  such as ownership,  permissions,
modification times,  etc.   Or perhaps cabal-sign should require or prohibit
certain values.   This data isn't very important in the context of cabal,
but making an informed choice here would require some investigation.

Currently this metadata is not protected,  mostly just so that it's easy
to generate the manifest from the command line.

Also, the entire metadata/ directory is not included in the manifest,
so we probably need to define a fairly tight policy of what is allowed
to be in that directory and what is not.   We certainly don't want unsigned
data to proliferate in the metadata directory,  especially metadata with
a vague or unclear purpose.   We would certainly want to set Hackage up
to reject any packages that put source code into said directory.

-}

type Manifest = [ (HexHash, PosixPath) ]

data ManifestInfo
   = FileHash !HexHash
   | DirectoryName

type ManifestEntry = (ManifestInfo, PosixPath)

type ManifestString = L.ByteString

type HexHash = S.ByteString
type PosixPath = FilePath

data Options
   = SumAndSign FilePath
   | Verify FilePath
   | PrintManifest FilePath

main = do
  (cmd:archive:_) <- getArgs
  case cmd of
    "sign" -> sumAndSign archive
    "verify" -> verify archive
    "manifest" -> printManifest archive

type TarData = Tar.Entries (Either Tar.FormatError Tar.PortabilityError)

-- checkSecurity is redundant,  given that I'm only allowing files and directories at
-- the moment.   Calling checkPortability to avoid things such as .. in filenames
-- and to prohibit other things worth prohibiting.

readTarData :: FilePath -> IO TarData
readTarData fp = Tar.checkPortability . Tar.read . Gzip.decompress <$> L.readFile fp

calcManifest :: TarData -> Manifest
calcManifest = maybe (disallow "empty directories") id
             . canonicalizeManifestEntries
             . getManifestEntries

showManifest :: Manifest -> ManifestString
showManifest = L.concat . concatMap format
  where  format (hash,fp) = [L.fromChunks [hash], "  ", fromString fp, "\n"]

getManifestEntries :: TarData -> [ ManifestEntry ]
getManifestEntries tar =
    case result of
      Left err -> error (show err)
      Right x  -> x
  where
    result = Tar.foldEntries (fmap . (:) . getManifestEntry)
                             (Right [])
                             (Left)
                             tar

getManifestEntry :: Tar.Entry -> ManifestEntry
getManifestEntry e =
    case Tar.entryContent e of
      Tar.NormalFile content _size -> let !hash = hexHash content
                                       in (FileHash hash, posixPath e)

      Tar.Directory             -> (DirectoryName, posixPath e)
      Tar.SymbolicLink    _     -> disallow "symbolic links"
      Tar.HardLink        _     -> disallow "hard links"
      Tar.CharacterDevice _ _   -> disallow "character devices"
      Tar.BlockDevice     _ _   -> disallow "block devices"
      Tar.NamedPipe             -> disallow "named pipes"
      Tar.OtherEntryType  _ _ _ -> disallow "unknown entry types"

newtype ManifestError = ManifestError String

disallow :: String -> a
disallow name = error (name ++ " are not allowed in a cabal archive")

posixPath :: Tar.Entry -> PosixPath
posixPath = Tar.fromTarPathToPosixPath . Tar.entryTarPath

-- | computes the sha-256 hash,  in a hex format
hexHash :: L.ByteString -> HexHash
hexHash = fromString . Sha2.showBSasHex . Sha2.hash Sha2.SHA256

-- | removes the metadata directory and sorts the entries by the hash
canonicalizeManifestEntries :: [ ManifestEntry ] -> Maybe Manifest
canonicalizeManifestEntries entries =
    if all isMetaDir (emptyDirectories entries)
    then Just $ sort [ (hash, name) | (FileHash hash, name) <- entries
                                    , not (isMeta name)                ]
    else Nothing

isMeta :: FilePath -> Bool
isMeta fp = "/metadata/" `isPrefixOf` dropWhile (/= '/') fp

isMetaDir :: FilePath -> Bool
isMetaDir fp = "/metadata/" == dropWhile (/= '/') fp


emptyDirectories :: [ ManifestEntry ] -> [ FilePath ]
emptyDirectories es =
    [ d  | (DirectoryName, d) <- es ] \\ [  parent f | (FileHash _, f) <- es ]
  where
    parent = fst . Posix.splitFileName

sumAndSign :: FilePath -> IO ()
sumAndSign fp = do
  exists <- doesFileExist fp
  if not exists
     then error $ fp ++ " doesn't exist"
     else do entries  <- readTarData fp
             let manifest = calcManifest entries
             L.writeFile manifestFile (showManifest $ manifest)
             rawSystem "gpg" ["--detach-sign",manifestFile]
             removeFile manifestFile
             addSignature fp (manifestFile <.> "sig") (toEntryList entries)
  where manifestFile = translate ".manifest" fp


toEntryList :: TarData -> [Entry]
toEntryList arg =
  case result of
    Left err -> error ("tar reading error: " ++ show err)
    Right entries -> entries

  where result = Tar.foldEntries (fmap . (:))
                                 (Right [])
                                 Left
                                 arg


addSignature :: FilePath -> FilePath -> [Entry] -> IO ()
addSignature gz sig entries = do
  signature <- L.readFile sig
  case liftA2 (,) (Tar.toTarPath False (makeSigName gz))
                  (Tar.toTarPath True  (metaName gz)   ) of
    Left err -> error err
    Right (spath,mpath) -> do

      let notIsMetaDir e =  Tar.entryContent e /= Directory
                         || isMetaDir (posixPath e)
          sigEntry   = Tar.fileEntry spath signature
          metaDir    = Tar.directoryEntry mpath
          entries'   = metaDir : sigEntry : filter (notIsMetaDir) entries
      L.writeFile gz (Gzip.compress (Tar.write entries'))
      removeFile sig


metaName gz = projectName gz </> "metadata"

projectName = dropWhile (=='-') . translate "" . takeFileName

makeSigName gz = metaName gz </> filename gz where
  filename = translate ".sig" . reverse . drop 1 . dropWhile (/='-') . reverse . takeFileName

translate ext = (++ ext) . dropSigned . dropExtension . dropExtension where
  dropSigned x | isSuffixOf ".signed" x = dropExtension x
               | otherwise = x

verify :: FilePath -> IO ()
verify fp = do
  exists <- doesFileExist fp
  if not exists
     then error $ fp ++ " doesn't exist"
     else do entries <- readTarData fp
             case find isSig (toEntryList entries) of
               Nothing    -> error $ "unable to find " ++ sigName ++ " in archive"
               Just entry -> do
                 L.writeFile sum (showManifest . calcManifest $ entries)
                 L.writeFile sig (getEntryFileContent entry)
                 rawSystem "gpg" ["--verify",sig,sum]
                 removeFile sum
                 removeFile sig

  where sigName = makeSigName fp
        sum = translate ".sum" fp
        isSig = (==sigName) . Tar.entryPath
        sig = translate ".sig" fp

getEntryFileContent entry =
  case Tar.entryContent entry of
    NormalFile bytes _ -> bytes
    _ -> error "malformed signature in the tar archive"

printManifest :: FilePath -> IO ()
printManifest fp = do
  exists <- doesFileExist fp
  if not exists
     then error $ fp ++ " doesn't exist"
     else do entries <- readTarData fp
             L.putStr (showManifest . calcManifest $ entries)

package rpm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	rpmtag_HEADERSIGNATURES  = 62   // RPM_BIN_TYPE
	rpmtag_HEADERIMMUTABLE   = 63   // RPM_BIN_TYPE
	rpmtag_HEADERI18NTABLE   = 100  // RPM_STRING_ARRAY_TYPE
	rpmtag_NAME              = 1000 // RPM_STRING_TYPE
	rpmtag_VERSION           = 1001 // RPM_STRING_TYPE
	rpmtag_RELEASE           = 1002 // RPM_STRING_TYPE
	rpmtag_SUMMARY           = 1004 // RPM_I18NSTRING_TYPE
	rpmtag_DESCRIPTION       = 1005 // RPM_I18NSTRING_TYPE
	rpmtag_BUILDTIME         = 1006 // RPM_INT32_TYPE
	rpmtag_BUILDHOST         = 1007 // RPM_STRING_TYPE
	rpmtag_SIZE              = 1009 // RPM_INT32_TYPE
	rpmtag_DISTRIBUTION      = 1010 // RPM_STRING_TYPE
	rpmtag_VENDOR            = 1011 // RPM_STRING_TYPE
	rpmtag_LICENSE           = 1014 // RPM_STRING_TYPE
	rpmtag_PACKAGER          = 1015 // RPM_STRING_TYPE
	rpmtag_GROUP             = 1016 // RPM_I18NSTRING_TYPE
	rpmtag_URL               = 1020 // RPM_STRING_TYPE
	rpmtag_OS                = 1021 // RPM_STRING_TYPE
	rpmtag_ARCH              = 1022 // RPM_STRING_TYPE
	rpmtag_PREIN             = 1023 // RPM_STRING_TYPE
	rpmtag_POSTIN            = 1024 // RPM_STRING_TYPE
	rpmtag_PREUN             = 1025 // RPM_STRING_TYPE
	rpmtag_POSTUN            = 1026 // RPM_STRING_TYPE
	rpmtag_OLDFILENAMES      = 1027 // RPM_STRING_ARRAY_TYPE
	rpmtag_FILESIZES         = 1028 // RPM_INT32_TYPE
	rpmtag_FILEMODES         = 1030 // RPM_INT16_TYPE
	rpmtag_FILEDEVS          = 1033 // RPM_INT16_TYPE
	rpmtag_FILEMTIMES        = 1034 // RPM_INT32_TYPE
	rpmtag_FILEMD5           = 1035 // RPM_STRING_ARRAY_TYPE
	rpmtag_FILELINKTOS       = 1036 // RPM_STRING_ARRAY_TYPE
	rpmtag_FILEFLAGS         = 1037 // RPM_INT32_TYPE
	rpmtag_FILEUSERNAME      = 1039 // RPM_STRING_ARRAY_TYPE
	rpmtag_FILEGROUPNAME     = 1040 // RPM_STRING_ARRAY_TYPE
	rpmtag_SOURCERPM         = 1044 // RPM_STRING_TYPE
	rpmtag_FILEVERIFYFLAGS   = 1045 // RPM_INT32_TYPE
	rpmtag_ARCHIVESIZE       = 1046 // RPM_INT32_TYPE
	rpmtag_PROVIDENAME       = 1047 // RPM_STRING_ARRAY_TYPE
	rpmtag_REQUIREFLAGS      = 1048 // RPM_INT32_TYPE
	rpmtag_REQUIRENAME       = 1049 // RPM_STRING_ARRAY_TYPE
	rpmtag_REQUIREVERSION    = 1050 // RPM_STRING_ARRAY_TYPE
	rpmtag_CONFLICTFLAGS     = 1053 // RPM_INT32_TYPE
	rpmtag_CONFLICTNAME      = 1054 // RPM_STRING_ARRAY_TYPE
	rpmtag_CONFLICTVERSION   = 1055 // RPM_STRING_ARRAY_TYPE
	rpmtag_RPMVERSION        = 1064 // RPM_STRING_TYPE
	rpmtag_CHANGELOGTIME     = 1080 // RPM_INT32_TYPE
	rpmtag_CHANGELOGNAME     = 1081 // RPM_STRING_ARRAY_TYPE
	rpmtag_CHANGELOGTEXT     = 1082 // RPM_STRING_ARRAY_TYPE
	rpmtag_PREINPROG         = 1085 // RPM_STRING_TYPE
	rpmtag_POSTINPROG        = 1086 // RPM_STRING_TYPE
	rpmtag_PREUNPROG         = 1087 // RPM_STRING_TYPE
	rpmtag_POSTUNPROG        = 1088 // RPM_STRING_TYPE
	rpmtag_OBSOLETENAME      = 1090 // RPM_STRING_ARRAY_TYPE
	rpmtag_COOKIE            = 1094 // RPM_STRING_TYPE
	rpmtag_FILEDEVICES       = 1095 // RPM_INT32_TYPE
	rpmtag_FILEINODES        = 1096 // RPM_INT32_TYPE
	rpmtag_FILELANGS         = 1097 // RPM_STRING_ARRAY_TYPE
	rpmtag_PROVIDEFLAGS      = 1112 // RPM_INT32_TYPE
	rpmtag_PROVIDEVERSION    = 1113 // RPM_STRING_ARRAY_TYPE
	rpmtag_OBSOLETEFLAGS     = 1114 // RPM_INT32_TYPE
	rpmtag_OBSOLETEVERSION   = 1115 // RPM_STRING_ARRAY_TYPE
	rpmtag_DIRINDEXES        = 1116 // RPM_INT32_TYPE
	rpmtag_BASENAMES         = 1117 // RPM_STRING_ARRAY_TYPE
	rpmtag_DIRNAMES          = 1118 // RPM_STRING_ARRAY_TYPE
	rpmtag_OPTFLAGS          = 1122 // RPM_STRING_TYPE
	rpmtag_DISTURL           = 1123 // RPM_STRING_TYPE
	rpmtag_PAYLOADFORMAT     = 1124 // RPM_STRING_TYPE
	rpmtag_PAYLOADCOMPRESSOR = 1125 // RPM_STRING_TYPE
	rpmtag_PAYLOADFLAGS      = 1126 // RPM_STRING_TYPE
	rpmtag_RHNPLATFORM       = 1131 // RPM_STRING_TYPE
	rpmtag_PLATFORM          = 1132 // RPM_STRING_TYPE

	rpmsigtag_DSA         = 267  // RPM_BIN_TYPE
	rpmsigtag_RSA         = 268  // RPM_BIN_TYPE
	rpmsigtag_SHA1        = 269  // RPM_STRING_TYPE
	rpmsigtag_SIZE        = 1000 // RPM_INT32_TYPE
	rpmsigtag_PGP         = 1002 // RPM_BIN_TYPE
	rpmsigtag_MD5         = 1004 // RPM_BIN_TYPE
	rpmsigtag_GPG         = 1005 // RPM_BIN_TYPE
	rpmsigtag_PAYLOADSIZE = 1007 // RPM_INT32_TYPE

	rpm_lead_size   = 96
	rpm_header_size = 16
	rpm_index_size  = 16
)

var (
	rpm_endian = binary.BigEndian
)

type ChangeLogEntry struct {
	Name string
	Text string
	Time time.Time
}

type Conflict struct {
	Name    string
	Flags   int32
	Version string
}

type Obsolete struct {
	Name    string
	Flags   int32
	Version string
}

type Require struct {
	Name    string
	Flags   int32
	Version string
}

type Provide struct {
	Name    string
	Flags   int32
	Version string
}

type File struct {
	Name  string
	Flags int32
	Size  int64
}

type Package struct {
	Architecture string
	ArchiveSize  int64
	BuildHost    string
	BuildTime    time.Time
	ChangeLog    []ChangeLogEntry
	Conflicts    []Conflict
	Description  string
	Distribution string
	Filename     string
	Files        []File
	Group        string
	Homepage     string
	License      string
	Modified     time.Time
	Name         string
	Obsoletes    []Obsolete
	Packager     string
	Provides     []Provide
	Release      string
	Requires     []Require
	RPMVersion   string
	Size         int64
	SourceRPM    string
	Summary      string
	Vendor       string
	Version      string
}

type rpm_lead struct {
	magic    uint32
	major    byte
	minor    byte
	pkgtype  int16
	archnum  int16
	name     [66]byte
	osnum    int16
	sigtype  int16
	reserved [16]byte
}

// aligned on 8-byte boundaries
type rpm_header struct {
	magic    uint32
	reserved [4]byte
	nindex   int32
	hsize    int32
}

type rpm_index struct {
	tag    int32
	kind   int32
	offset int32
	count  int32
}

func Parse(filename string) (*Package, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "Cannot open %s", filename)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, errors.Wrapf(err, "Cannot stat %s", filename)
	}
	rpm := &Package{
		Filename: filename,
		Modified: info.ModTime(),
	}
	if err := read_lead(rpm, file); err != nil {
		return nil, err
	} else if err := parse_signature(file); err != nil {
		return nil, err
	} else if err := parse_header(rpm, file); err != nil {
		return nil, err
	}
	return rpm, nil
}

func read_lead(rpm *Package, reader io.Reader) error {
	lead := &rpm_lead{}
	if err := binary.Read(reader, rpm_endian, &lead.magic); err != nil {
		return errors.Wrap(err, "Error reading package lead")
	} else if err := binary.Read(reader, rpm_endian, &lead.major); err != nil {
		return errors.Wrap(err, "Error reading package lead")
	} else if err := binary.Read(reader, rpm_endian, &lead.minor); err != nil {
		return errors.Wrap(err, "Error reading package lead")
	} else if err := binary.Read(reader, rpm_endian, &lead.pkgtype); err != nil {
		return errors.Wrap(err, "Error reading package lead")
	} else if err := binary.Read(reader, rpm_endian, &lead.archnum); err != nil {
		return errors.Wrap(err, "Error reading package lead")
	} else if err := binary.Read(reader, rpm_endian, &lead.name); err != nil {
		return errors.Wrap(err, "Error reading package lead")
	} else if err := binary.Read(reader, rpm_endian, &lead.osnum); err != nil {
		return errors.Wrap(err, "Error reading package lead")
	} else if err := binary.Read(reader, rpm_endian, &lead.sigtype); err != nil {
		return errors.Wrap(err, "Error reading package lead")
	} else if err := binary.Read(reader, rpm_endian, &lead.reserved); err != nil {
		return errors.Wrap(err, "Error reading package lead")
	} else if lead.magic != 0xedabeedb {
		return errors.New("Invalid package lead magic")
	} else if lead.major != 3 {
		return errors.New("Unsupported package major version")
	} else if lead.minor != 0 {
		return errors.New("Unsupported package minor version")
	} else if lead.pkgtype != 0 {
		return errors.New("Unsupported package type")
	} else if lead.osnum != 1 {
		return errors.New("Unsupported package os")
	} else if lead.sigtype != 5 {
		return errors.New("Unsupported package signature type")
	}
	rpm.RPMVersion = fmt.Sprintf("%d.%d", lead.major, lead.minor)
	return nil
}

func parse_signature(reader io.Reader) error {
	header, err := read_header(reader)
	if err != nil {
		return errors.Wrap(err, "Error reading package header")
	}
	skiplen := int((header.nindex * rpm_index_size) + header.hsize)
	if remainder := skiplen % 8; remainder != 0 {
		skiplen += 8 - remainder
	}
	return skip_bytes(reader, skiplen)
}

func parse_header(rpm *Package, reader io.Reader) error {
	header, err := read_header(reader)
	if err != nil {
		return err
	}
	records, err := read_records(reader, int(header.nindex))
	if err != nil {
		return err
	}
	buffer := make([]byte, header.hsize)
	if _, err := io.ReadFull(reader, buffer); err != nil {
		return errors.Wrap(err, "Error parsing package header")
	}
	int32_value := func(offset int32) int32 {
		var value int32
		binary.Read(bytes.NewReader(buffer[offset:]), rpm_endian, &value)
		return value
	}
	int32_values := func(offset, count int32) (values []int32) {
		for i := int32(0); i < count; i++ {
			var value int32
			binary.Read(bytes.NewReader(buffer[offset:]), rpm_endian, &value)
			values = append(values, value)
			offset += 4
		}
		return
	}
	string_value := func(offset int32) string {
		return strings.TrimSpace(string_from_buffer(buffer[offset:]))
	}
	string_values := func(offset, count int32) (values []string) {
		for i := int32(0); i < count; i++ {
			value := string_from_buffer(buffer[offset:])
			values = append(values, strings.TrimSpace(value))
			offset += int32(len(value) + 1)
		}
		return
	}
	var oldfilenames []string
	var dirindexes []int32
	var basenames []string
	var dirnames []string
	for _, record := range records {
		switch record.tag {
		case rpmtag_ARCH:
			rpm.Architecture = string_value(record.offset)
		case rpmtag_ARCHIVESIZE:
			rpm.ArchiveSize = int64(int32_value(record.offset))
		case rpmtag_BASENAMES:
			basenames = string_values(record.offset, record.count)
		case rpmtag_BUILDHOST:
			rpm.BuildHost = string_value(record.offset)
		case rpmtag_BUILDTIME:
			rpm.BuildTime = time.Unix(int64(int32_value(record.offset)), 0)
		case rpmtag_CHANGELOGNAME:
			if rpm.ChangeLog == nil {
				rpm.ChangeLog = make([]ChangeLogEntry, record.count)
			}
			for index, value := range string_values(record.offset, record.count) {
				rpm.ChangeLog[index].Name = strings.TrimSpace(value)
			}
		case rpmtag_CHANGELOGTEXT:
			if rpm.ChangeLog == nil {
				rpm.ChangeLog = make([]ChangeLogEntry, record.count)
			}
			for index, value := range string_values(record.offset, record.count) {
				rpm.ChangeLog[index].Text = strings.TrimSpace(value)
			}
		case rpmtag_CHANGELOGTIME:
			if rpm.ChangeLog == nil {
				rpm.ChangeLog = make([]ChangeLogEntry, record.count)
			}
			for index, value := range int32_values(record.offset, record.count) {
				rpm.ChangeLog[index].Time = time.Unix(int64(value), 0)
			}
		case rpmtag_CONFLICTFLAGS:
			if rpm.Conflicts == nil {
				rpm.Conflicts = make([]Conflict, record.count)
			}
			for index, value := range int32_values(record.offset, record.count) {
				rpm.Conflicts[index].Flags = value
			}
		case rpmtag_CONFLICTNAME:
			if rpm.Conflicts == nil {
				rpm.Conflicts = make([]Conflict, record.count)
			}
			for index, value := range string_values(record.offset, record.count) {
				rpm.Conflicts[index].Name = strings.TrimSpace(value)
			}
		case rpmtag_CONFLICTVERSION:
			if rpm.Conflicts == nil {
				rpm.Conflicts = make([]Conflict, record.count)
			}
			for index, value := range string_values(record.offset, record.count) {
				rpm.Conflicts[index].Version = strings.TrimSpace(value)
			}
		case rpmtag_DESCRIPTION:
			rpm.Description = string_value(record.offset)
		case rpmtag_DIRINDEXES:
			dirindexes = int32_values(record.offset, record.count)
		case rpmtag_DIRNAMES:
			dirnames = string_values(record.offset, record.count)
		case rpmtag_DISTRIBUTION:
			rpm.Distribution = string_value(record.offset)
		case rpmtag_FILEFLAGS:
			if rpm.Files == nil {
				rpm.Files = make([]File, record.count)
			}
			for index, value := range int32_values(record.offset, record.count) {
				rpm.Files[index].Flags = value
			}
		case rpmtag_FILESIZES:
			if rpm.Files == nil {
				rpm.Files = make([]File, record.count)
			}
			for index, value := range int32_values(record.offset, record.count) {
				rpm.Files[index].Size = int64(value)
			}
		case rpmtag_GROUP:
			rpm.Group = string_value(record.offset)
		case rpmtag_LICENSE:
			rpm.License = string_value(record.offset)
		case rpmtag_NAME:
			rpm.Name = string_value(record.offset)
		case rpmtag_OBSOLETEFLAGS:
			if rpm.Obsoletes == nil {
				rpm.Obsoletes = make([]Obsolete, record.count)
			}
			for index, value := range int32_values(record.offset, record.count) {
				rpm.Obsoletes[index].Flags = value
			}
		case rpmtag_OBSOLETENAME:
			if rpm.Obsoletes == nil {
				rpm.Obsoletes = make([]Obsolete, record.count)
			}
			for index, value := range string_values(record.offset, record.count) {
				rpm.Obsoletes[index].Name = strings.TrimSpace(value)
			}
		case rpmtag_OBSOLETEVERSION:
			if rpm.Obsoletes == nil {
				rpm.Obsoletes = make([]Obsolete, record.count)
			}
			for index, value := range string_values(record.offset, record.count) {
				rpm.Obsoletes[index].Version = strings.TrimSpace(value)
			}
		case rpmtag_OLDFILENAMES:
			oldfilenames = string_values(record.offset, record.count)
		case rpmtag_PACKAGER:
			rpm.Packager = string_value(record.offset)
		case rpmtag_PROVIDEFLAGS:
			if rpm.Provides == nil {
				rpm.Provides = make([]Provide, record.count)
			}
			for index, value := range int32_values(record.offset, record.count) {
				rpm.Provides[index].Flags = value
			}
		case rpmtag_PROVIDENAME:
			if rpm.Provides == nil {
				rpm.Provides = make([]Provide, record.count)
			}
			for index, value := range string_values(record.offset, record.count) {
				rpm.Provides[index].Name = strings.TrimSpace(value)
			}
		case rpmtag_PROVIDEVERSION:
			if rpm.Provides == nil {
				rpm.Provides = make([]Provide, record.count)
			}
			for index, value := range string_values(record.offset, record.count) {
				rpm.Provides[index].Version = strings.TrimSpace(value)
			}
		case rpmtag_RELEASE:
			rpm.Release = string_value(record.offset)
		case rpmtag_REQUIREFLAGS:
			if rpm.Requires == nil {
				rpm.Requires = make([]Require, record.count)
			}
			for index, value := range int32_values(record.offset, record.count) {
				rpm.Requires[index].Flags = value
			}
		case rpmtag_REQUIRENAME:
			if rpm.Requires == nil {
				rpm.Requires = make([]Require, record.count)
			}
			for index, value := range string_values(record.offset, record.count) {
				rpm.Requires[index].Name = strings.TrimSpace(value)
			}
		case rpmtag_REQUIREVERSION:
			if rpm.Requires == nil {
				rpm.Requires = make([]Require, record.count)
			}
			for index, value := range string_values(record.offset, record.count) {
				rpm.Requires[index].Version = strings.TrimSpace(value)
			}
		case rpmtag_SIZE:
			rpm.Size = int64(int32_value(record.offset))
		case rpmtag_SOURCERPM:
			rpm.SourceRPM = string_value(record.offset)
		case rpmtag_SUMMARY:
			rpm.Summary = string_value(record.offset)
		case rpmtag_URL:
			rpm.Homepage = string_value(record.offset)
		case rpmtag_VENDOR:
			rpm.Vendor = string_value(record.offset)
		case rpmtag_VERSION:
			rpm.Version = string_value(record.offset)
		}
	}
	if basenames != nil && dirnames != nil && dirindexes != nil {
		if rpm.Files == nil {
			rpm.Files = make([]File, len(basenames))
		}
		for index, value := range basenames {
			basename := strings.TrimSpace(value)
			dirname := strings.TrimSpace(dirnames[dirindexes[index]])
			rpm.Files[index].Name = dirname + basename
		}
	} else if oldfilenames != nil {
		if rpm.Files == nil {
			rpm.Files = make([]File, len(oldfilenames))
		}
		for index, value := range oldfilenames {
			rpm.Files[index].Name = strings.TrimSpace(value)
		}
	}
	return nil
}

func read_header(reader io.Reader) (*rpm_header, error) {
	header := &rpm_header{}
	if err := binary.Read(reader, rpm_endian, &header.magic); err != nil {
		return nil, errors.Wrap(err, "Error reading package header")
	} else if err := binary.Read(reader, rpm_endian, &header.reserved); err != nil {
		return nil, errors.Wrap(err, "Error reading package header")
	} else if err := binary.Read(reader, rpm_endian, &header.nindex); err != nil {
		return nil, errors.Wrap(err, "Error reading package header")
	} else if err := binary.Read(reader, rpm_endian, &header.hsize); err != nil {
		return nil, errors.Wrap(err, "Error reading package header")
	} else if header.magic != 0x8eade801 {
		return nil, errors.New("Invalid package header magic")
	} else if header.nindex < 0 {
		return nil, errors.New("Invalid package header nindex")
	} else if header.hsize < 0 {
		return nil, errors.New("Invalid package header hsize")
	}
	return header, nil
}

func read_index(reader io.Reader) (*rpm_index, error) {
	index := &rpm_index{}
	if err := binary.Read(reader, rpm_endian, &index.tag); err != nil {
		return nil, errors.Wrap(err, "Error reading package index")
	} else if err := binary.Read(reader, rpm_endian, &index.kind); err != nil {
		return nil, errors.Wrap(err, "Error reading package index")
	} else if err := binary.Read(reader, rpm_endian, &index.offset); err != nil {
		return nil, errors.Wrap(err, "Error reading package index")
	} else if err := binary.Read(reader, rpm_endian, &index.count); err != nil {
		return nil, errors.Wrap(err, "Error reading package index")
	}
	return index, nil
}

func read_records(reader io.Reader, count int) ([]*rpm_index, error) {
	var records []*rpm_index
	for i := 0; i < count; i++ {
		index, err := read_index(reader)
		if err != nil {
			return nil, err
		}
		records = append(records, index)
	}
	return records, nil
}

func skip_bytes(reader io.Reader, amount int) error {
	buffer := make([]byte, amount)
	_, err := io.ReadFull(reader, buffer)
	if err != nil {
		return errors.Wrap(err, "Error skipping bytes")
	}
	return nil
}

func string_from_buffer(buffer []byte) string {
	length := bytes.IndexByte(buffer, 0)
	if length < 0 {
		length = len(buffer)
	}
	return string(buffer[0:length])
}

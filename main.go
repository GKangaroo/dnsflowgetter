// origin
package main

import (
    "fmt"
    "log"
    "os"
    "os/exec"
    "encoding/json"
    "path/filepath"
    "sort"
    "strings"
    "strconv"
    "sync"
    "time"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/xitongsys/parquet-go/writer"
    "github.com/xitongsys/parquet-go/reader"
    "github.com/xitongsys/parquet-go-source/local"
    "github.com/miekg/dns"
	"unicode/utf8"
)

var (
    sldMap   = make(map[string]bool)
    logMutex sync.Mutex
    dnsLogs  []map[string]interface{}
    logDir   = "./"
)

const recentSize = 80

const netcard = "ens2f0np0"
const destination = "/home/guiqx/DNSMon/tmpNetworkFlow"
const keyPath = "/home/user/DWTF/DNSMon/traffic_get/privatekey"

var (
    recentQueriesRing []string
    recentSet         sync.Map
    writeIndex        uint64
	recentMutex       sync.Mutex
)

type DNSLog struct {
    Timestamp    int64   `parquet:"name=timestamp, type=INT64"`
    SrcIP        string   `parquet:"name=src_ip, type=BYTE_ARRAY, convertedtype=UTF8"`
    SrcPort      int32   `parquet:"name=src_port, type=INT32"`
    DestIP       string   `parquet:"name=dst_ip, type=BYTE_ARRAY, convertedtype=UTF8"`
    DestPort     int32   `parquet:"name=dst_port, type=INT32"`
    QueryDomain  string   `parquet:"name=query_domain, type=BYTE_ARRAY, convertedtype=UTF8"`
    QueryType    string   `parquet:"name=query_type, type=BYTE_ARRAY, convertedtype=UTF8"`
    ResponseCode int16    `parquet:"name=response_code, type=INT32"`
    AnswerCount  int32    `parquet:"name=answer_count, type=INT32"`
    Answers []string `parquet:"name=answers, type=LIST, valuetype=BYTE_ARRAY, convertedtype=UTF8"`
    MinTTL int32    `parquet:"name=min_ttl, type=INT32"`
    AvgTTL int32    `parquet:"name=avg_ttl, type=INT32"`
    QueryID      int32   `parquet:"name=query_id, type=INT32"`
}


func main() {
    recentQueriesRing = make([]string, recentSize)
    handle, err := pcap.OpenLive(netcard, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    ticker := time.NewTicker(1 * time.Minute) 
    cleanTicker := time.NewTicker(2 * time.Minute)

    go func() {
        for range ticker.C {
            writeLogsToFile()
        }
    }()

    go func() {
        for range cleanTicker.C {
            cleanOldLogs()
        }
    }()

    for packet := range packetSource.Packets() {
        go processPacket(packet)
    }
}

func qtypeToString(qtype uint16) string {
	if name, ok := dns.TypeToString[qtype]; ok {
		return name
	}
	return "UNKNOWN"
}

func processPacket(packet gopacket.Packet) {
    dnsLayer := packet.Layer(layers.LayerTypeDNS)
    if dnsLayer == nil {
        return
    }
    dns, ok := dnsLayer.(*layers.DNS)
    if !ok {
        log.Println("DNS layer parsing failed")
        return
    }

    networkLayer := packet.NetworkLayer()
    transportLayer := packet.TransportLayer()
    if networkLayer == nil || transportLayer == nil {
        return
    }
    srcIP, dstIP := networkLayer.NetworkFlow().Endpoints()
    srcPort, dstPort := transportLayer.TransportFlow().Endpoints()

    srcPortInt, err := strconv.Atoi(srcPort.String())
    if err != nil {
        log.Println("Failed to convert srcPort:", err)
        return
    }

    dstPortInt, err := strconv.Atoi(dstPort.String())
    if err != nil {
        log.Println("Failed to convert dstPort:", err)
        return
    }

    packetTimestamp := packet.Metadata().Timestamp
    timestamp := packetTimestamp.Unix()
    // fmt.Println(timestamp,reflect.TypeOf(timestamp))
    
    if len(dns.Questions) == 0 {
        return
    }
    
    uniqueKey := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
        networkLayer.NetworkFlow().Src().String(),
        networkLayer.NetworkFlow().Dst().String(),
        transportLayer.TransportFlow().Src().String(),
        transportLayer.TransportFlow().Dst().String(),
        string(dns.Questions[0].Name),
        fmt.Sprintf("0x%x", dns.ID))

    if !recordRecentQuery(uniqueKey) {
        return
    }

    
    if dns.QR == false {
        for _, question := range dns.Questions {
            qname := string(question.Name)
            qtype := qtypeToString(uint16(question.Type))
            // if(qtype != "AAAA" && qtype != "A" && qtype != "NS" && len(qname) <= 3){
            //     fmt.Println(qname,qtype)
            // }
            if qtype == "UNKNOWN" {
                continue
            }
    
            logEntry := map[string]interface{}{
                "timestamp":       timestamp,
                "src_ip":          srcIP.String(),
                "src_port":        srcPortInt,
                "dest_ip":         dstIP.String(),
                "dest_port":       dstPortInt,
                "query_domain":    qname,
                "query_type":      qtype,
                "response_code":   int32(-1),
                "answer_count":    int32(-1),
                "answers":         []string{},
                // "ttl":      []int32{},
                "min_ttl":  int32(-1),
                "avg_ttl":  int32(-1),
                // "authority":       []string{},
                // "authorityttl":    []int32{},
                // "additional":      []string{},
                // "additionalttl":   []int32{},
                "query_id":        dns.ID,
            }
            appendDNSLog(logEntry)
        } 
    }else { 
        if dns.ID == 0 {
            return 
        }

        for _, question := range dns.Questions {
            qname := string(question.Name)
            qtype := qtypeToString(uint16(question.Type))
            // if(qtype != "AAAA" && qtype != "A" && qtype != "NS" && len(qname) <= 3){
            //     fmt.Println(qname,qtype)
            // }
            if qtype == "UNKNOWN" {
                continue
            }

            logEntry := map[string]interface{}{
                "timestamp":       timestamp,
                "src_ip":          srcIP.String(),
                "src_port":        srcPortInt,
                "dest_ip":         dstIP.String(),
                "dest_port":       dstPortInt,
                "query_domain":    qname,
                "query_type":      qtype,
                "response_code":   int32(dns.ResponseCode),
                "answer_count":    int32(len(dns.Answers)),
                "answers":         extractDNSAnswers(dns),
                "min_ttl":  extractMinTTL(dns),
                "avg_ttl":  extractAvgTTL(dns),
                "query_id":        dns.ID,
            }
            appendDNSLog(logEntry)
        } 

    }
}

func extractDNSAnswers(dns *layers.DNS) []string {
    var answers []string
    for _, answer := range dns.Answers {
        // fmt.Println(qtypeToString(uint16(answer.Type)))
        if(answer.Type.String() != "Unknown"){
            answers = append(answers, dnsResourceDataToString(&answer))
        }
    }
    return answers
}

func extractMinTTL(dns *layers.DNS) int32 {
    if len(dns.Answers) == 0 {
        return 0 
    }
    minTTL := int32(dns.Answers[0].TTL)
    for _, answer := range dns.Answers {
        if int32(answer.TTL) < minTTL {
            minTTL = int32(answer.TTL)
        }
    }
    return minTTL
}

func extractAvgTTL(dns *layers.DNS) int32 {
    if len(dns.Answers) == 0 {
        return 0 
    }
    
    var totalTTL int32
    for _, answer := range dns.Answers {
        totalTTL += int32(answer.TTL)
    }
    return int32(float64(totalTTL) / float64(len(dns.Answers)) + 0.5)
}


func extractAnswersTTL(dns *layers.DNS) []int32 {
    var ttl []int32
    ttl = append(ttl, -111)
    for _, answer := range dns.Answers {
        ttl = append(ttl, int32(answer.TTL))
    }
    ttl = append(ttl, -222)
    for _, authority := range dns.Authorities {
        ttl = append(ttl, int32(authority.TTL))
    }
    ttl = append(ttl, -333)
    for _, additional := range dns.Additionals {
        ttl = append(ttl, int32(additional.TTL))
    }
    return ttl
}

func appendDNSLog(logEntry map[string]interface{}) {
    logMutex.Lock()
    defer logMutex.Unlock()
    dnsLogs = append(dnsLogs, logEntry)
}

func isValidDNSLog(logEntry map[string]interface{}) bool {
    strFields := []string{"src_ip", "dest_ip", "query_domain", "query_type"}

    for _, f := range strFields {
        val, ok := logEntry[f].(string)
        if !ok || !utf8.ValidString(val) {
            return false
        }
    }

    return true
}

func writeLogsToFile() {
    logMutex.Lock()
    defer logMutex.Unlock()

    if len(dnsLogs) == 0 {
        return
    }

    os.MkdirAll(logDir, 0755)

    loc, _ := time.LoadLocation("Asia/Shanghai") 
    now := time.Now().In(loc).Format("200601021504") 
    filename := fmt.Sprintf("%s.parquet", now)

    fw, err := local.NewLocalFileWriter(filename)
    defer fw.Close()

    pw, err := writer.NewParquetWriter(fw, new(DNSLog), 4)
    if err != nil {
        log.Printf("Failed to create Parquet writer: %v", err)
        return
    }
    
    for _, logEntry := range dnsLogs {
		if !isValidDNSLog(logEntry) {
			continue
		}
        record := DNSLog{
            Timestamp:      logEntry["timestamp"].(int64),
            SrcIP:          logEntry["src_ip"].(string),
            SrcPort:        int32(logEntry["src_port"].(int)),
            DestIP:         logEntry["dest_ip"].(string),
            DestPort:       int32(logEntry["dest_port"].(int)),
            QueryDomain:    logEntry["query_domain"].(string),
            QueryType:      logEntry["query_type"].(string),
            ResponseCode:   int16(logEntry["response_code"].(int32)), 
            AnswerCount:    logEntry["answer_count"].(int32),

            Answers:        logEntry["answers"].([]string),
            MinTTL:         logEntry["min_ttl"].(int32),
            AvgTTL:         logEntry["avg_ttl"].(int32),
            
            QueryID:        int32(logEntry["query_id"].(uint16)), 
        }

        if err := pw.Write(record); err != nil {
            log.Printf("Failed to write Parquet record: %v", err)
        }
    }
    
    pw.WriteStop()
    fw.Close()

    defer func() {
        if !validateParquetFile(filename) {
            log.Printf("Parquet file %s is corrupted!", filename)
        } else {
            log.Printf("Parquet file %s written successfully.", filename)
        }
    
        dnsLogs = nil
    }()
}

func validateParquetFile(filename string) bool {
    fr, err := local.NewLocalFileReader(filename)
    if err != nil {
        log.Printf("Failed to open Parquet file for validation: %v", err)
        return false
    }
    defer fr.Close()

    pr, err := reader.NewParquetReader(fr, new(DNSLog), 4)
    if err != nil {
        log.Printf("Failed to create Parquet reader: %v", err)
        return false
    }
    defer pr.ReadStop()
    
    num := int(pr.GetNumRows())
    if num == 0 {
        log.Printf("Parquet file is empty or unreadable: %s", filename)
        return false
    }

    return true
}


func dnsResourceDataToString(rr *layers.DNSResourceRecord) string {
    data := map[string]interface{}{"Type": rr.Type.String()}

    switch rr.Type {
    case layers.DNSTypeA, layers.DNSTypeAAAA:
        data["Data"] = rr.IP.String()
    case layers.DNSTypeCNAME:
        data["Data"] = string(rr.CNAME)
    case layers.DNSTypeNS:
        data["Data"] = string(rr.NS)
    case layers.DNSTypePTR:
        data["Data"] = string(rr.PTR)
    case layers.DNSTypeMX:
        data["Data"] = map[string]interface{}{
            "Name":       rr.MX.Name,
            "Preference": rr.MX.Preference,
        }
    case layers.DNSTypeTXT:
        var txts []string
        for _, txt := range rr.TXTs {
            txts = append(txts, string(txt))
        }
        data["Data"] = txts
    case layers.DNSTypeSOA:
        data["Data"] = map[string]interface{}{
            "MName":   rr.SOA.MName,
            "RName":   rr.SOA.RName,
            "Serial":  rr.SOA.Serial,
            "Refresh": rr.SOA.Refresh,
            "Retry":   rr.SOA.Retry,
            "Expire":  rr.SOA.Expire,
            "Minimum": rr.SOA.Minimum,
        }
    case layers.DNSTypeSRV:
        data["Data"] = map[string]interface{}{
            "Target":   rr.SRV.Name,
            "Port":     rr.SRV.Port,
            "Priority": rr.SRV.Priority,
            "Weight":   rr.SRV.Weight,
        }
    default:
        data["Data"] = fmt.Sprintf("%x", rr.Data)
    }
    
    jsonData, err := json.Marshal(data)
    if err != nil {
        return "{}"
    }
    return string(jsonData)
}

func scpFileWithKey(filePath, user, host, destination, keyPath string) error {
	expectScript := fmt.Sprintf(`
spawn scp -i %s %s %s@%s:%s
expect eof
`, keyPath, filePath, user, host, destination)

	tmpFile := "scp_script.exp"
	err := os.WriteFile(tmpFile, []byte(expectScript), 0700)
	if err != nil {
		return fmt.Errorf("failed to create expect script: %v", err)
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("expect", tmpFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func cleanOldLogs() {
    logMutex.Lock()
    defer logMutex.Unlock()

    entries, err := os.ReadDir(logDir)
    if err != nil {
        log.Printf("Error reading directory: %v", err)
        return
    }

    var logFiles []os.FileInfo
    for _, entry := range entries {
        if !entry.IsDir() {
            info, err := entry.Info()
            if err != nil {
                log.Printf("Error getting file info: %v", err)
                continue
            }
            if strings.HasPrefix(info.Name(), "2025") && strings.HasSuffix(info.Name(), ".parquet") {
                logFiles = append(logFiles, info)
            }
        }
    }

    if len(logFiles) <= 2 {
        return
    }

    sort.Slice(logFiles, func(i, j int) bool {
        return logFiles[i].ModTime().After(logFiles[j].ModTime())
    })

    user := "guiqx"
    host := "202.112.47.184"
    
    for _, fileInfo := range logFiles[3:] {
        filePath := filepath.Join(logDir, fileInfo.Name())
        log.Printf("Deleting old log file: %s\n", filePath)
        scpFileWithKey(filePath, user, host, destination, keyPath)
        
        os.Remove(filePath)
    }
}

func recordRecentQuery(key string) bool {
    recentMutex.Lock()
    defer recentMutex.Unlock()

    if _, ok := recentSet.Load(key); ok {
        return false
    }

    idx := int(writeIndex % uint64(recentSize))
    writeIndex++

    oldKey := recentQueriesRing[idx]
    if oldKey != "" {
        recentSet.Delete(oldKey)
    }

    recentQueriesRing[idx] = key
    recentSet.Store(key, true)

    return true
}

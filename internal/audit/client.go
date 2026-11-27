package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Send is a producer's one record: it writes rec on its producer socket and returns nil only on the ACK, so an effect
// that waits on it runs only after the record is durable (§9).
func Send(sock string, rec map[string]any) error {
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := c.Write(append(b, '\n')); err != nil {
		return err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	var rep Reply
	if err != nil || json.Unmarshal(line, &rep) != nil {
		return fmt.Errorf("audit: no reply: %v", err)
	}
	if !rep.OK {
		return fmt.Errorf("audit: NACK %s", rep.Code)
	}
	return nil
}

// Copyright © 2026 @sudocelestia. All rights reserved.
//
// PROPRIETARY AND CONFIDENTIAL SOURCE CODE.
//
// No licence, permission or authorisation is granted to use, copy, modify,
// compile, execute, distribute, publish, sublicense or otherwise exploit this
// file, except to the limited extent unavoidably permitted by applicable law
// or GitHub's Terms of Service.
//
// See the LICENSE file at the repository root for the complete terms.

package linuxamd64feasibility

import (
	"errors"
	"io"
)

const (
	clone3GateByte  = 'g'
	clone3ReadyByte = 'r'
)

func runClone3Bootstrap(gate io.Reader, ready io.Writer, prepare func() error) error {
	if prepare == nil {
		return errors.New("missing clone3 bootstrap preparation")
	}
	if err := readClone3Byte(gate, clone3GateByte); err != nil {
		return err
	}
	if err := prepare(); err != nil {
		return err
	}
	if err := writeClone3Byte(ready, clone3ReadyByte); err != nil {
		return err
	}
	return readClone3Byte(gate, clone3GateByte)
}

func readClone3Byte(reader io.Reader, expected byte) error {
	var value [1]byte
	count, err := io.ReadFull(reader, value[:])
	if err != nil {
		return err
	}
	if count != 1 || value[0] != expected {
		return errors.New("unexpected clone3 gate byte")
	}
	return nil
}

func writeClone3Byte(writer io.Writer, value byte) error {
	count, err := writer.Write([]byte{value})
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("short clone3 ready write")
	}
	return nil
}

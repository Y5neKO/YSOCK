package logger

import (
	"log"
	"sync/atomic"
)

type Level int32

const (
	LevelError Level = iota
	LevelInfo
	LevelDebug
)

var currentLevel atomic.Int32

func SetLevel(l Level) { currentLevel.Store(int32(l)) }
func GetLevel() Level  { return Level(currentLevel.Load()) }

func Debugf(tag, format string, args ...interface{}) {
	if GetLevel() >= LevelDebug {
		log.Printf("[DBG] [%s] "+format, append([]interface{}{tag}, args...)...)
	}
}

func Infof(tag, format string, args ...interface{}) {
	if GetLevel() >= LevelInfo {
		log.Printf("[%s] "+format, append([]interface{}{tag}, args...)...)
	}
}

func Errorf(tag, format string, args ...interface{}) {
	log.Printf("[ERR] [%s] "+format, append([]interface{}{tag}, args...)...)
}

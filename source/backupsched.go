package main

import (
	"fmt"
	"time"
)

// Backups run as a Scheduler task (action "backup", one per cluster is usual).  Versions v583-v591 kept their own
// schedule in the backup block (enabled, hours, at); migrateBackupSchedule turns that into a task the first time the
// configuration is read, so nothing changes for a cluster that had backups on.

const backupTaskID = "backup"

// backupScheduled says whether an enabled backup task runs on the node.
func backupScheduled(tasks []SchedTask, node string) bool {
	for i := range tasks {
		if t := &tasks[i]; t.Action == "backup" && !t.Disabled && t.appliesTo(node) {
			return true
		}
	}
	return false
}

func migrateBackupSchedule(d *DNSConfig) {
	b := d.Backup
	if b == nil || (!b.Enabled && b.Hours == 0 && b.At == "") {
		return
	}
	if b.Enabled && len(b.Targets)+len(b.Host) > 0 {
		has := false
		for _, t := range d.Schedule {
			has = has || t.Action == "backup" || t.ID == backupTaskID
		}
		if !has {
			d.Schedule = append(d.Schedule, oldBackupTask(b.Hours, b.At, time.Local))
		}
	}
	b.Enabled, b.Hours, b.At = false, 0, ""
}

// oldBackupTask is the task that does what the old settings did: every N hours, or once a day at At (the node's own
// clock, 02:30 when empty; the Scheduler works in UTC).  The nodes spread over five minutes, as before.
func oldBackupTask(hours int, at string, loc *time.Location) SchedTask {
	t := SchedTask{ID: backupTaskID, Name: "Back up every node", Action: "backup"}
	if hours > 0 {
		t.Freq, t.Every, t.At, t.Until = "hourly", hours, "00:00", "00:05"
		if hours == 1 {
			t.Every = 0
		}
		return t
	}
	var hh, mm int
	if !backupAtRe.MatchString(at) {
		at = "02:30"
	}
	fmt.Sscanf(at, "%d:%d", &hh, &mm)
	now := time.Now().In(loc)
	u := time.Date(now.Year(), now.Month(), now.Day(), hh, mm, 0, 0, loc).UTC()
	t.Freq, t.At, t.Until = "daily", u.Format("15:04"), u.Add(5*time.Minute).Format("15:04")
	return t
}

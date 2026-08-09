// Removable example data for the first run. Every record carries
// demo: true so it can be cleanly removed and never silently mixes
// with real work.

import { createAction, newId } from './model.js';
import { atTime, addDays, startOfDay } from './timeutil.js';

export function buildDemoData(now) {
  const today = startOfDay(now);
  const yesterday = addDays(today, -1);
  const iso = (d) => d.toISOString();

  const actions = [
    createAction({
      title: 'Compare the two KomReg rollout dates and choose one',
      definitionOfDone: 'The decision is posted in Linear and the team is tagged.',
      type: 'decide', status: 'ready', project: 'KomReg',
      estimateMinutes: 25, energy: 'high', demo: true,
      sourceRef: { type: 'linear', externalId: 'KOM-142', url: 'https://linear.app', label: 'KOM-142' },
    }),
    createAction({
      title: 'Reply to the customer about the export scope',
      definitionOfDone: 'Reply sent; open questions turned into Linear issues.',
      type: 'do', status: 'scheduled', project: 'Report',
      scheduledFor: iso(atTime(today, '16:15')),
      estimateMinutes: 20, energy: 'medium', demo: true,
    }),
    createAction({
      title: 'Product sync',
      type: 'do', status: 'scheduled', project: '',
      scheduledFor: iso(atTime(today, '15:00')),
      estimateMinutes: 45, hard: true, contexts: ['meeting'], demo: true,
    }),
    createAction({
      title: 'Review the DocSync migration draft',
      definitionOfDone: 'Comments left in Docmost; author pinged.',
      type: 'review', status: 'ready', project: 'DocSync',
      estimateMinutes: 40, energy: 'medium', demo: true,
      lastTouchedAt: iso(addDays(today, -6)), updatedAt: iso(addDays(today, -6)),
      createdAt: iso(addDays(today, -9)),
      sourceRef: { type: 'docmost', externalId: null, url: 'https://docmost.com', label: 'Migration draft' },
    }),
    createAction({
      title: 'Follow up: security questionnaire for GPS-S',
      type: 'followUp', status: 'waiting', project: 'GPS-S',
      waitingFor: 'Daniel', waitingSince: iso(addDays(today, -2)),
      followUpAt: iso(atTime(today, '11:00')), demo: true,
    }),
    createAction({
      title: 'Verify the API rate limits with the new vendor',
      type: 'do', status: 'blocked', project: 'GPS-S',
      blockedReason: 'Sandbox access hasn’t been provisioned yet.',
      estimateMinutes: 30, demo: true,
    }),
    createAction({
      title: 'Prepare tomorrow’s rollout decision material',
      type: 'do', status: 'scheduled', project: 'KomReg',
      scheduledFor: iso(atTime(addDays(today, 1), '09:30')),
      estimateMinutes: 45, energy: 'high', demo: true,
    }),
    createAction({
      title: 'Weekly triage of Canny suggestions',
      type: 'review', status: 'scheduled', project: '',
      scheduledFor: iso(atTime(addDays(today, 2), '10:00')),
      estimateMinutes: 30, demo: true,
      recurrenceRule: { freq: 'weekly', weekdays: [], n: 1, unit: 'days', paused: false },
      sourceRef: { type: 'canny', externalId: null, url: 'https://canny.io', label: 'Canny board' },
    }),
    createAction({
      title: 'Sort the conference notes somewhere sensible',
      type: 'do', status: 'inbox', demo: true,
    }),
  ];

  const trailEvent = (kind, title, project, at) => ({
    id: newId('t'), at: iso(at), kind, actionId: null, title, project, detail: '', demo: true,
  });

  const trail = [
    trailEvent('completed', 'Clarified export requirement with support', 'Report', atTime(yesterday, '09:40')),
    trailEvent('decision', 'Chose the phased rollout for GPS-S', 'GPS-S', atTime(yesterday, '11:20')),
    trailEvent('unblocked', 'Cleared the staging data dependency', 'KomReg', atTime(yesterday, '14:05')),
    trailEvent('completed', 'Sent the weekly status to stakeholders', '', atTime(yesterday, '16:30')),
  ];

  // A couple of believable moves earlier today, time permitting.
  if (now.getHours() >= 11) {
    trail.push(trailEvent('completed', 'Unblocked engineering on the export format', 'Report', atTime(today, '10:17')));
  }
  if (now.getHours() >= 9) {
    trail.push(trailEvent('completed', 'Reviewed the rollout proposal', 'KomReg', atTime(today, '08:51')));
  }

  return { actions, trail };
}

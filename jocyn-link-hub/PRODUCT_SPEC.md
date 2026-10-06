# JO₵YN Creator OS — Product Design Specification

## Product design thesis

JO₵YN Creator OS is not a dashboard with a link-in-bio page attached. It is one operating environment with two coordinated surfaces:

- **Private OS:** strategy, creation, campaign execution, scheduling, media, analytics and AI.
- **Public Hub:** the owned mobile destination that audiences reach from Instagram and other profiles.

The private system is the source of truth. The public experience is one output of that system.

The first release intentionally supports one workspace and one primary creator identity: **JO₵YN**. The workspace selector, data model and navigation are designed to expand later without exposing multi-brand complexity in V1.

# BUILD NOW

## 1. Command Center

**Purpose:** Daily operating environment.

**Primary goal:** Tell the creator what matters now and make the next action obvious.

**Top-to-bottom hierarchy:**
1. Workspace-aware header and global search.
2. Daily priority / current release action.
3. Today’s priorities.
4. Content pipeline.
5. Active campaign.
6. Public Link Hub preview.
7. AI recommendations.
8. Current week / content gaps.

**Primary action:** Create.

**Secondary actions:** Open campaign, ask AI, edit Link Hub, open calendar.

**Empty state:** Replace missing sections with guided setup prompts, never zero-state metric cards.

**Loading:** Skeletons preserve card dimensions and hierarchy.

**Error:** Keep local planning data visible; isolate failed integrations inside the relevant module.

**Mobile:** Recompose to priority feed + bottom dock. Do not reproduce desktop sidebar.

**AI:** Proactive recommendations should always include a reason and a next action.

## 2. Content Studio

**Purpose:** One home for ideas through publication.

**States:** Idea → Draft → Needs Review → Ready → Scheduled → Published → Repurpose → Archived.

**Views:** List, pipeline and calendar.

**Primary action:** Create content.

**Secondary:** Upload media, filter, repurpose.

**Core content object:** title, source idea, campaign, format, platforms, state, media, copy variants, schedule and performance.

**Repurposing:** One source item fans out to platform-native adaptations. Never imply that the same caption should be copied everywhere.

## 3. Idea Engine

**Purpose:** Convert an intent into an executable content system.

**Open canvas placeholder:** “Describe what you want to create, promote, launch, grow, or experiment with…”

**Flow:** Idea → Strategy → Concepts → Drafts → Media needs → Platform adaptations → Schedule → Publish → Measure → Next action.

Preset workflows speed up common intents but never replace open input.

## 4. Calendar

**Purpose:** Show content rhythm, campaign windows and gaps.

**V1 views:** Week and month.

**Campaign awareness:** A release date or event date should visually influence recommended posting windows.

**Opportunity state:** Empty calendar cells may be labeled “content gap” and offer an AI recommendation.

## 5. Campaigns

**Purpose:** Group execution around one outcome.

**V1 fields:** objective, status, start/end, project/release, content, assets, tasks, Link Hub actions and performance.

**Primary action:** New campaign.

**TALK BOUT** is the current example of the active-campaign pattern.

## 6. Projects / Releases

Hierarchy:

Project / Release
→ Campaign
→ Content
→ Assets
→ Links
→ Timeline
→ Performance

This prevents singles and campaigns from becoming isolated work.

## 7. Link Hub Manager

**Purpose:** Manage the public site like a modular website, not a form full of URLs.

**Desktop layout:**
- Left: block library
- Center: live mobile preview
- Right: selected block settings

**Block controls:** visibility, reordering, schedule, campaign association, artwork, copy, destination and analytics.

**V1 blocks:** profile, featured release, smart music link, video, event, email signup, custom CTA.

## 8. Public Link Hub

The public hub remains mobile-first and optimized for in-app browsers.

Core hierarchy:
1. JO₵YN identity
2. Current era
3. Featured release
4. Music / watch / live destinations
5. Owned audience capture
6. Persistent contact/share action

Campaign artwork supplies most of the interface color.

## 9. Analytics

**Purpose:** Decision support, not a wall of metrics.

Each insight should answer:
- What happened?
- Why does it matter?
- What should I do next?

Core V1 categories: profile visits, link clicks, content saves, content engagement, top destination and campaign CTR.

## 10. Media Library

Reusable assets should be classified by media type and association:
- campaign
- project/release
- platform content
- brand asset

No duplicate-upload workflow should be required for each post.

## 11. Contextual AI

AI is available globally and receives:
- active workspace
- current screen
- selected campaign/project
- brand voice
- recent content
- public Link Hub state
- analytics context

AI should produce structured objects that can become content, tasks, campaign changes or Link Hub updates.

## 12. Search + Command Palette

`⌘ K / Ctrl K`

Core commands:
- Create post
- Ask AI
- Open Content Studio
- Open Calendar
- Open active campaign
- Edit Link Hub
- Open Analytics
- Search media

Search later expands across content, ideas, campaigns, projects, links, assets, tasks and AI conversations.

# Navigation

Primary:
1. Command Center
2. Content Studio
3. Ideas
4. Calendar
5. Campaigns
6. Projects
7. Link Hub
8. Analytics
9. Media

Utility:
- Create
- Search / command palette
- Notifications
- AI
- Settings
- View public hub

The workspace selector sits above navigation so context is always visible.

# Design system

## Typography
- Interface: Inter / system sans fallback
- Technical metadata: DM Mono / monospace fallback
- Use tight display tracking only for major headings.

## Color
The OS is restrained and neutral. Campaign artwork supplies color.

Core tokens:
- background
- raised surface
- secondary surface
- primary text
- muted text
- border
- paper / inverse action
- semantic green, amber, blue, red, violet

## Shape
- 10–13px: controls
- 14–18px: content cards
- 20–28px: major surfaces
- pills reserved for status and compact metadata

## Motion
Motion is purposeful:
- navigation state
- modal/drawer entry
- status changes
- drag feedback
- preview updates
- publishing confirmations
- AI streaming

Honor reduced-motion settings.

# Responsive model

## Desktop
Persistent navigation + multi-column command environment.

## Tablet
Collapsible navigation and two-column cards.

## Mobile
Bottom dock:
- Home
- Content
- Create
- AI
- More

Prioritize:
- today
- approvals
- creation
- scheduling
- AI
- performance highlights
- Link Hub editing

# Empty states

Empty states teach and act.

Bad: “No campaigns.”

Good:
“You’re not running a campaign yet. Create one and we’ll turn the goal into content, tasks, Link Hub updates and a publishing plan.”

Every empty state has one primary action.

# Onboarding

1. Create workspace
2. Name the identity
3. Choose primary goal
4. Connect first platform
5. Add public links
6. Confirm / refine brand voice
7. Upload basic assets
8. Build public Link Hub
9. Generate first content idea
10. Enter Command Center

Keep the flow short. Infer whenever possible.

# BUILD NEXT

- Persistent database for workspace, content, campaigns, links and assets
- Authentication
- Real Link Hub publishing from manager
- Real email signup storage
- Media uploads
- Platform OAuth
- Publishing capability matrix
- Scheduled content
- First-party analytics event collection
- Real command search
- AI structured actions
- Campaign-linked analytics
- Live link health checks
- Notifications and task reminders

# FUTURE

- Multiple brands / workspaces
- Teams and permissions
- Approval workflows
- Agency / client mode
- Advanced automation
- Automated repurposing agents
- Paid campaign management
- Audience segmentation
- CRM layer
- Monetization
- Automated campaign execution
- Cross-workspace reporting

Complexity should remain hidden until the user enables the capability.

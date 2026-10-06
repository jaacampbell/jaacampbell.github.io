# JO₵YN Creator OS — Product Specification

## Product design thesis

JO₵YN Creator OS is one operating environment with two coordinated surfaces:

- Private OS: strategy, creation, campaign execution, scheduling, media, analytics and AI.
- Public Hub: the owned mobile destination reached from Instagram and other profiles.

The private OS is the source of truth. The public site is one published output of the creator workspace.

V1 intentionally supports one workspace and one primary creator identity: JO₵YN. The workspace selector, navigation and object model are designed to expand later without exposing multi-brand complexity now.

## BUILD NOW

### Command Center
Purpose: the daily operating environment.
Primary goal: tell the creator what matters now and make the next action obvious.
Hierarchy: daily priority, today's tasks, content pipeline, active campaign, public Link Hub preview, AI recommendations and weekly rhythm.
Primary action: Create.
Mobile: priority feed plus bottom dock rather than a shrunken desktop sidebar.
AI: every recommendation should include the reason and the next action.

### Content Studio
States: Idea, Draft, Needs Review, Ready, Scheduled, Published, Repurpose and Archived.
Views: list, pipeline and calendar.
The core content object should retain campaign, format, platform adaptations, media, copy variants, schedule and performance.
Repurposing is one source object fanning out into platform-native variants.

### Idea Engine
Open canvas first, presets second.
Flow: Idea to Strategy to Concepts to Drafts to Media Needs to Platform Adaptations to Schedule to Publish to Measure to Next Action.

### Calendar
Shows content rhythm, release windows and gaps.
Empty gaps can become AI-assisted opportunities instead of dead space.

### Campaigns
A campaign groups goal, timeline, project, content, assets, tasks, Link Hub actions and performance.
TALK BOUT is the active reference campaign in the prototype.

### Projects / Releases
Project or Release
-> Campaign
-> Content
-> Assets
-> Links
-> Timeline
-> Performance

### Link Hub Manager
Desktop structure:
Left: block library
Center: live mobile preview
Right: selected block settings

Core controls: visibility, ordering, scheduling, campaign association, artwork, copy, destinations and analytics.

### Public Link Hub
Hierarchy:
1. JO₵YN identity
2. Current era
3. Featured release
4. Music / watch / live destinations
5. Audience capture
6. Persistent contact and share action

### Analytics
Decision support rather than vanity metrics.
Every insight should answer:
- What happened?
- Why does it matter?
- What should I do next?

### Media Library
Reusable assets should be associated with projects, campaigns, platform content and brand identity.

### Contextual AI
AI receives current workspace, screen, selected campaign/project, brand voice, recent content, public Link Hub state and analytics context.
AI should eventually produce structured actions, not disconnected chat output.

### Search and command palette
Shortcut: Command K / Control K.
Core commands: create post, ask AI, open Content Studio, open Calendar, open active campaign, edit Link Hub, open Analytics and search media.

## Navigation

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

Utilities:
Create, Search, Notifications, AI, Settings and View Public Hub.

## Design system

Neutral dark operating environment. Campaign artwork provides most color.
Use strong hierarchy, restrained borders, clear status language and modest motion.
Major surfaces use larger radii than utility controls.
Pills are reserved for compact status or metadata.
Respect reduced-motion settings.

## Responsive behavior

Desktop: persistent sidebar and multi-column command center.
Tablet: collapsible sidebar and reduced columns.
Mobile: bottom dock with Home, Content, Create, AI and More.

## BUILD NEXT

- Persistent database
- Authentication
- Real Link Hub publishing from manager
- Email signup persistence
- Media uploads
- Platform OAuth
- Platform capability matrix
- Scheduled content
- First-party analytics events
- Structured AI actions
- Campaign-linked analytics
- Link health checks
- Notifications and reminders

## FUTURE

- Multiple brands and workspaces
- Teams and permissions
- Approval workflows
- Agency and client mode
- Advanced automation
- Automated repurposing
- Audience segmentation
- CRM layer
- Monetization
- Paid campaigns
- AI agents
- Automated campaign execution

Complexity should remain hidden until the user enables the capability.

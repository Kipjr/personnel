<?php

namespace App\Console\Commands;

use Spatie\GoogleCalendar\Event as GEvent;
use Spatie\GoogleCalendar\Resource;
use App\Models\Event as LEvent;
use App\Models\Location;
use Carbon\Carbon;
use RRule\RRule;
use Illuminate\Console\Command;

class CalendarSync extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'reservation:CalendarSync';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Command description';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
        $config = config('baragenda');
        $this->google = $config['google'];
    }

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {


        ##
        ## Sync using ID and update timestamp
        ##
       
        #get local $array1 = array("green", "red", "blue");
        $events_local = LEvent::whereBetween('datetime_start', [Carbon::today()->startOfDay()->addMonths(-1), Carbon::today()->addMonths(1)])->get();
        if(!($events_local->isEmpty())){
            $id_local = $events_local->mapWithKeys(function ($item) {
                return  array($item->google_event_id=>$item);
            });
        } else{ $id_local=collect(); }

        #get remote $array2 = array("green", "yellow", "red");
        $events_remote1 = GEvent::get(Carbon::today()->startOfDay()->addMonths(-1), Carbon::today()->addMonths(1),array(),  $this->google['calendar']['public']); #public calendar
        $events_remote2 = GEvent::get(Carbon::today()->startOfDay(), Carbon::today()->addMonths(1),array(),  $this->google['calendar']['private']); #private calendar
        $events_remote=$events_remote1->concat($events_remote2); #combine the collections

        $events_remoteParent = $events_remote2->map(function ($ev, $key) {
            if($ev->recurringEventId != null){
                return GEvent::find($ev->recurringEventId,$ev->getCalendarId());
            }
            
        });
        $events_remoteParent=$events_remoteParent->unique()->whereNotNull()->values();     #get all parent events 
        $events_remote=$events_remoteParent->concat($events_remote); #combine the collections

        #print_r($events_remoteParent);die;
        
        $id_remote = $events_remote->mapWithKeys(function ($item) {
            return  array($item->id=>$item);
        });

        #do diff/intersect on all datasets
        $id_left=$id_local->diffKeys($id_remote); #$id_left=array_values(array_diff($id_local,$id_remote)); #$array("blue"); 
        $id_intersect=$id_local->intersectByKeys($id_remote); #$id_intersect=array_values(array_intersect($id_local,$id_remote)) # intersect $array("green",  "red"); 
        $id_right=$id_remote->diffKeys($id_local); #$id_right=array_values(array_diff($id_remote,$id_local));  #$array("yellow");

        #
        # Event exist in local db and online | if id remote==id local
        #
        if($id_intersect->count() > 0){
            $id_intersect->each(function ($item, $key) {
                #
                #   Check timestamp | if local is newer-> sync to google (update publish remoteley)
                # 
                if($item->updated_at > $item->google_updated) {
                    if($item->status != 'publish') {
                        #GEvent::find($item->id,env('GOOGLE_CALENDAR_ID_PUBLIC'))->delete(); Deletes event from Calendar
                    }
                    #
                    #  sync to google (delete remotelely)
                    # 
                    else {
                        // $event = Event::find($item->google_event_id);
                        // $event->name = $item->title;
                        // $event->save();
                    }
                }
                else {
                    # This means that the event has been updated outside of this locall application... this should perhaps update the local db
                }
            
            });
        }
        #
        # Event exist in local db only | if id local does not exist remotely
        #
        if($id_left->count() > 0){
            $id_left->each(function ($item, $key) {
            #   create (if not delete)
                if($item->status == 'publish'){
                  #create
                }
            });
        }
        #
        # Event exist in Remote only| only if made online / app and has not synced with local db
        #
        if($id_right->count() > 0){
            $id_right->each(function ($item, $key) {
               #sync to local

               #DEBUG
                    if($item->summary){ 
                        try {
                            #$this->info(print_r($item->getSortDate()));
                        }
                        catch (Exception $e) {}
                    }
                $event = LEvent::create([

                    'summary'               =>  $item->summary,
                    'description'           =>  $item->description,
                    'datetime_start'        =>  $item->startDateTime ? $item->startDateTime->format('Y-m-d H:i:s') : null ,
                    'datetime_end'          =>  $item->endDateTime ? $item->endDateTime->format('Y-m-d H:i:s') : null, 
                    'date_start'            =>  $item->startDate ? $item->startDate->toDateString() : null ,
                    'date_end'              =>  $item->endDate ? $item->endDate->toDateString() : null ,
                    'recurring_start'       =>  null, #for parent
                    'recurring_end'         =>  null,  #for parent
                    'rrule'                 =>  $item->recurrence[0] ?? null,
                    'all_day'               =>  $item->isAllDayEvent(),
                    'location'              =>  $item->location, #$item.atrendees.email in location.email ? location.id : item.loctionid
                    'attendees'             =>  json_encode($item->attendees),
                    'entrypoints'           =>  $item->conferenceData ? json_encode($item->conferenceData['entryPoints']) : null ,
                    'status'                => 'published',
                    'google_calendar_id'    =>  $item->getCalendarId(),
                    'google_event_id'       =>  $item->id,
                    'google_parent_event_id'=>  $item->recurringEventId,
                    'google_updated'        =>  Carbon::parse($item->updated)->format('Y-m-d H:i:s'),
                    'google_created'        =>  Carbon::parse($item->created)->format('Y-m-d H:i:s'),
                    'guests_caninviteothers'=>  $item->guestsCanInviteOthers ? True : False,
                    'guests_canmodify'      =>  $item->guestsCanModify ? True : False,
                    'guests_canseeotherguests'=> $item->guestsCanSeeOtherGuests ? True : False,
                    'organizer_displayname' =>  $item->organizer->displayName,
                    'creator_displayname'   =>  $item->creator->displayName,
                    'organizer_email'       =>  $item->organizer->email,
                    'creator_email'         =>  $item->creator->email,
                    'htmllink'              =>  $item->htmlLink,
                    'updated_by'            =>  900913,
                    'committee_id'          =>  null,
                ]);
                $event->save();
            });
        } 

        $Resources = Resource::get();
        foreach($Resources as $ResourceItem) {
            $location = Location::updateOrCreate(
                ['resource_id'   => $ResourceItem['id']],
                [ 
                'name'          => $ResourceItem['name'], 
                'generatedname' => $ResourceItem['generatedname'], 
                'capacity'      => $ResourceItem['capacity'],
                'floorname'     => $ResourceItem['floorname'], 
                'floorsection'  => $ResourceItem['floorsection'],  
                'features'      => json_encode($ResourceItem['features']), 
                'email'         => $ResourceItem['email'], 

            ]);
        }


        return 0;
    }
}

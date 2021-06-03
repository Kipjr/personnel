@section('scripts')
	<script src="{{ asset('js/agenda.js') }}" defer></script>
	<script src="{{ asset('js/moment-timezone.js') }}" defer></script>
@section('styles')
	<link href="{{ asset('css/agenda.css') }}" rel="stylesheet">
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/tempusdominus-bootstrap-4/5.0.0-alpha14/css/tempusdominus-bootstrap-4.min.css" />
@extends('base')

@section('content')
    <div class="container" style="min-width: 1280px;">
        <div class="row">
            <div class="col-md-12 ">
                <div class="card">
                    <div class="card-header">
					</div>
					<div class="card-block" >


						<div class="border-div ag-header">
							<nav class="navbar navbar-expand-md navbar-light bg-white shadow-sm">
								<div class="container">
									<div class="collapse navbar-collapse" id="navbarSupportedContent">
										<ul class="navbar-nav mr-auto">
											{{--<li class="nav-item"><a class="nav-link" href="#">Vandaag</a></li>--}}
										</ul>
									</div>
								</div>
							</nav>
						</div>
						<div class="border-div ag-topleft">

						</div>

						<div class="border-div ag-full" style="">
							<div class="border-div ag-left" style="">
                                @admin
                                    <div class="ag-create-wrapper">
                                        <a href={{ route('agenda.edit')}}>
                                            <div class="ag-create-container">
                                                <button class="ag-create-button"  >
                                                    <span class="ag-create-span"></span>
                                                    <div class="ag-create-shape"></div>
                                                    <span class="ag-create-shape2">
                                                        <div class="ag-create-shape3">
                                                            <svg width="36" height="36" viewBox="0 0 36 36">
                                                                <path fill="#34A853" d="M16 16v14h4V20z"></path>
                                                                <path fill="#4285F4" d="M30 16H20l-4 4h14z"></path>
                                                                <path fill="#FBBC05" d="M6 16v4h10l4-4z"></path>
                                                                <path fill="#EA4335" d="M20 16V6h-4v14z"></path>
                                                                <path fill="none" d="M0 0h36v36H0z"></path>
                                                            </svg>
                                                        </div>
                                                        <div class="ag-create-text"  >Nieuw</div>
                                                    </span>
                                                </button>
                                            </div>
                                        </a>
                                    </div>
                                @endadmin
								<div class="cal_left">
									<div class="row">
										<div class="col-12">
											<div style="overflow:hidden; padding-left:15px; padding-right:15px; ">
												<div class="form-group">
													<div class="row">
														<div class="col-md-12">
                                                            <div id="datetimepicker13" style="border: 1px solid #0000000d"></div>
                                                            <form id="dateform" autocomplete="off" action="{{ route('agenda') }}" method='POST' style="display:none;">
                                                                {{ csrf_field() }}
                                                                <input type="text" id="date" name="date" />
                                                                <input type="submit" />
                                                            </form>
														</div>
													</div>
                                                </div>

												<script type="text/javascript">
												var data
													$(function () {
														$('#datetimepicker13').datetimepicker({
                                                            defaultDate: moment("{{$selectedDate->translatedFormat('Y-m-d')}}"),
                                                            locale:'nl',
                                                            timeZone: 'Europe/Amsterdam',
															buttons: {showToday: true},
															calendarWeeks: true,
															inline: true,
															format: 'L'
														});
													});
													$( document ).ready(function() {
														$("#datetimepicker13").on("change.datetimepicker", function (e) {
															iso=moment(e.date._d).toISOString();
                                                            console.log(iso)
                                                            $("#date").val(iso)
                                                            $("#dateform").submit()
														});
													})




												</script>
											</div>
										</div>
									</div>
								</div>
							</div>
							<div class="border-div ag-right" style=" ">
								<div class="border-div ag-right-main" style= "">
									<div class="border-div ag-right-main-data" style="">
										<div class="border-div data-grid" style="">
											<div class="border-div data-grid-top" style=""">
												<div class="border-div grid-top-filler" style="">

												</div>
												<div class="border-div grid-top-days" style="">
													<div class="border-div top-days-list " style="">
														@foreach(array_values($dateList) as $i => $date)
															<div class="vertDayColumn border-div ">
																<div class="vertDayColumn-data border-div ">
																	<div id="dayname_{{$i}}" class="vertDayColumn-dayname border-div ">
																		{{$date['carbon']->translatedFormat('D')}}
																	</div>
																	<div id="dayno_{{$i}}" class="vertDayColumn-dayno border-div ">
																		{{$date['carbon']->translatedFormat('d')}}
																	</div>
																</div>
															</div>
														@endforeach
													</div>
													<div  class="grid-top-allday border-div" >
														<div  class="top-allday-data border-div" >
															<div  class="allday-data-list  border-div" >
																@php
																	$loopvar = 0;
																@endphp
																@foreach($allDayEvents as $i => $date)
                                                                    @foreach($date['events'] as $j => $event)
																		@if($event['shape']['size']>=1)
																			<div style="
																					width:{{ $event['shape']['size_day']*100}}%;
																					top: {{$loopvar}}em;
																					left: {{ ($event['shape']['pos_day'])*100 }}%;"
																				class="allday-data-item border-div" >
																				<div onclick="eventModal('{{ $event['object']['google_event_id'] }}')" class="allday-data-item-button">
																					<span class="allday-data-item-span">
																						{{$event['object']['summary']}}
																					</span>
																				</div>
																			</div>
																			@php
																				$loopvar ++;
																			@endphp
																		@endif
																	@endforeach
																@endforeach
															</div>
														</div>
													</div>
												</div>
											</div>
											<div class="border-div data-grid-bottom" style=" ">
												<div class="border-div grid-bottom-tabs" onload="scrollTo(0.5)" style="">
													<div class="border-div bottom-tabs-time" style="" >
														<div class="border-div tabs-time-list " style="" >
															<div class="vertTimeItem vertTimeItemCompact">
																<div class="vertTimeItemFont">
																	00:00
																</div>
															</div>
															<div class="vertTimeItem vertTimeItemCompact">
																<div class="vertTimeItemFont">
																	01:00
																</div>
															</div>
															<div class="vertTimeItem vertTimeItemCompact">
																<div class="vertTimeItemFont">
																	02:00
																</div>
															</div>
															<div class="vertTimeItem vertTimeItemCompact">
																<div class="vertTimeItemFont">
																	03:00
																</div>
															</div>
															<div class="vertTimeItem vertTimeItemCompact">
																<div class="vertTimeItemFont">
																	04:00
																</div>
															</div>
															<div class="vertTimeItem vertTimeItemCompact">
																<div class="vertTimeItemFont">
																	05:00
																</div>
															</div>
															<div class="vertTimeItem vertTimeItemCompact">
																<div class="vertTimeItemFont">
																	06:00
																</div>
															</div>
															<div class="vertTimeItem vertTimeItemCompact">
																<div class="vertTimeItemFont">
																	07:00
																</div>
															</div>
															<div class="vertTimeItem vertTimeItemCompact">
																<div class="vertTimeItemFont">
																	08:00
																</div>
															</div>
															<div class="vertTimeItem vertTimeItemCompact">
																<div class="vertTimeItemFont">
																	09:00
																</div>
															</div>
															<div class="vertTimeItem vertTimeItemCompact">
																<div class="vertTimeItemFont">
																	10:00
																</div>
															</div>
															<div class="vertTimeItem vertTimeItemCompact">
																<div class="vertTimeItemFont">
																	11:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">
																	12:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">
																	13:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">
																	14:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">
																	15:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">
																	16:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">
																	17:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">
																	18:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">
																	19:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">
																	20:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">
																	21:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">
																	22:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">
																	23:00
																</div>
															</div>
															<div class="vertTimeItem">
																<div class="vertTimeItemFont">

																</div>
															</div>
														</div>
													</div>
													<div class="border-div bottom-tabs-content" style="">
														<div class="border-div tabs-content-events" style="">
															@foreach(array_values($events) as $i => $date)
																<div id="grid_{{$i}}" class="border-div bottom-tabs-gridcell" style="position:relative">
																	@foreach($date['events'] as $j => $event)
																		@if($event['shape']['size']<1)
																			<div onclick="eventModal('{{ $event['object']['google_event_id'] }}')" class="{{ $event['source']=='Interne Agenda' ? 'event-button' : 'event-button2'}}"
																			style="z-index: {{$j+15}};top:
																				@if($event['shape']['pos']<=0.5) {{20/720*24*$event['shape']['pos'] *100}}% {{--20=time;720=total--}}
																				@else {{((40/720)*(24*($event['shape']['pos']-0.5))+(0.5*24*(20/720))) * 100}}% {{--20&40=time;720=total--}}
																				@endif; height:{{$event['shape']['size']*720}}px;">
																				<div class="event-button-data">
																					<div class="event-button-title">
																						{{ $event['object']['summary']   }}
																					</div>
																					<div class="event-button-time">
																						{{ $event['object']['datetime_start']->translatedFormat('H:i') }}-{{ $event['object']['datetime_end']->translatedFormat('H:i') }}
																					</div>
																				</div>
																			</div>
																		@endif
																	@endforeach
																</div>
															@endforeach
														</div>
													</div>
														<!-- Modal -->
														<div id="myModal" class="modal fade" role="dialog" >
															<div class="modal-dialog">

															<!-- Modal content-->
															<div class="modal-content">
																<div class="modal-body" style="min-height:300px;max-width: 448px;width: 448px; padding-left: 1.5rem;">
                                                                    <div class="row" style="height:136px;">
                                                                        Top image
                                                                    </div>
                                                                    <div class="row">
                                                                        <div class="col-12">
                                                                            <div class="row min-height40">
                                                                                <div class="col-1" data-toggle="tooltip" title="Summary">
                                                                                    <i class="fas fa-circle"></i>
                                                                                </div>
                                                                                <div class="col-11">
                                                                                    <h3 id="md_summary"></h3>
                                                                                </div>
                                                                            </div>
                                                                            <div class="row min-height40">
                                                                                <div class="col-1" data-toggle="tooltip" title="Location">
                                                                                    <i class="fas fa-city"></i>
                                                                                </div>
                                                                                <div class="col-11">
                                                                                    <p id="md_location"></p>
                                                                                </div>
                                                                            </div>
                                                                            <div class="row min-height40">
                                                                                <div class="col-1" data-toggle="tooltip" title="Room">
                                                                                    <i class="fas fa-door-open"></i>
                                                                                </div>
                                                                                <div class="col-11">
                                                                                    <p id="md_room"></p>
                                                                                </div>
                                                                            </div>
                                                                            <div class="row min-height40">
                                                                                <div class="col-1" data-toggle="tooltip" title="Attendees">
                                                                                    <i class="fas fa-users"></i>
                                                                                </div>
                                                                                <div class="col-11">
                                                                                    <p id="md_guests"></p>
                                                                                </div>
                                                                            </div>
                                                                            <div class="row min-height40">
                                                                                <div class="col-1" data-toggle="tooltip" title="Description">
                                                                                    <i class="fas fa-info-circle"></i>
                                                                                </div>
                                                                                <div class="col-11">
                                                                                    <p id="md_description"></p>
                                                                                </div>
                                                                            </div>
																			<div class="row min-height40">
                                                                                <div class="col-1" data-toggle="tooltip" title="Meet Link">
                                                                                    <i class="fas fa-briefcase"></i>
                                                                                </div>
                                                                                <div class="col-11">
                                                                                    <p id="md_meet"></p>
                                                                                </div>
                                                                            </div>
                                                                            <div class="row min-height40">
                                                                                <div class="col-1" data-toggle="tooltip" title="Calendar">
                                                                                    <i class="fas fa-calendar-day"></i>
                                                                                </div>
                                                                                <div class="col-11">
                                                                                    <p id="md_calendar"></p>
                                                                                </div>
                                                                            </div>
                                                                        </div>
                                                                    </div>
																</div>
																<div class="modal-footer">
                                                                    @admin
                                                                        <form id="editEventForm" autocomplete="off" action="{{ route('agenda.edit') }}" style="margin-block-end: 0em;" method='GET' >
                                                                            {{ csrf_field() }}
                                                                            <input type="hidden" id="editEventId" name="eventId" value="" />
                                                                            <input type="hidden" id="editCalendarId" name="calendarNo" value="" />
                                                                        <button type="submit" class="btn btn-default" >Aanpassen</button>
                                                                        </form>
                                                                    @endadmin
																    <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
																</div>
															</div>

															</div>
														</div>


												</div>
											</div>
										</div>
									</div>
								</div>
							</div>
						</div>



						{{-- <table class="table responsive-table agenda">
						<thead>
							<tr>
								<th>Datum</th>
								<th>Tijd</th>
								<th>Agenda</th>
								<th>Titel</th>
							</tr>
						</thead>
						<tbody>

					@foreach($events as $i => $date)
						@if(count($date['events'])<1) <tr><td>{{$date['carbon']->translatedFormat('l d F')}}</td><td></td><td></td><td></td></tr> @endif
						@foreach($date['events'] as $j => $event)
								<tr>
								<td>@if($j==0){{ $event['object']['datetime_start']->translatedFormat('l d F')  }}@endif</td>
									<td>{{ $event['object']['datetime_start']->translatedFormat('H:i') }}-{{ $event['object']['datetime_end']->translatedFormat('H:i') }} </td>
									<td>{{ $event['object']['google_calendar_id'] }}</td>
									<td>{{ $event['object']['summary']  }}</td>
								</tr>
						@endforeach
					@endforeach

						</tbody>
					</table> --}}
					</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script>
        function eventModal(google_event_id){
            //console.log(google_event_id)

            try {

                $.post("{{ route('agenda.getdate') }}", {
                    google_event_id: google_event_id,
                    "_token": "{{ csrf_token() }}",
                })
                .then(function(response){
                    event=response.data;
                    //console.log(event)
                    $('#editEventId').val(event.google_event_id);
                    $('#editCalendarId').val(event.google_calendar_id);

                    $('#md_summary').text(event.summary);
                    $('#md_location').text(event.location);
                    $('#md_room').text(event.attendees);
                    $('#md_guests').text(event.attendees);
                    $('#md_description').text(event.description);
                    $('#md_meet').text(event.entrypoints);
                    $('#md_calendar').text(event.calendar);

                    $("#myModal").modal()
                })
            }
            catch (err){
                console.log("error "+err)
            }


        }
    </script>
@endsection

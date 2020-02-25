@extends('base')

@section('content')
    <div class="container">
        <div class="row">
            <div class="col-md-12 ">
                <div class="card">
                    <div class="card-header">
                        @if(!isset($page) || $page == 0)
                            Diensten in de komende 2 weken
                        @else
                            Diensten tussen {{ reset($shifts)['carbon']->format('l d F') }} en {{ end($shifts)['carbon']->format('l d F') }}
                        @endif
						<hr>

						<a href="{{
                        $page == 1 ?
                            route('shifts') :
                            route('shifts.page', ['page' => (isset($page) ? $page-1 : -1)])
                    }}" class="pull-left btn">Previous</a>

                        <a href="{{
                        $page == -1 ?
                            route('shifts') :
                            route('shifts.page', ['page' => (isset($page) ? $page+1 : 1)])
                    }}" class="pull-right btn">Next</a>
                        <br class="clearfix"/>
					</div>
                    <div class="card-block">
                        @if (session('status'))
						<div class="alert alert-success">
							{{ session('status') }}
						</div>
                        @endif
						<br>
						<table class="table table-responsive diensten">
							<thead>
								<tr>
									<th>Datum</th>
								@foreach($shifttypes as $i => $type)
									<th>{{$type->title}}</th>
								@endforeach
									<th></th>
								</tr>
							</thead>
							<tbody>
						@foreach($shifts as $i => $shift)
                               <tr>
                               <td><a href="{{ route('shifts.date', ['date' => $i]) }}">{{ $shift['carbon']->format('l d F') }}</a></td>
						@foreach($shifttypes as $j => $type)

									<td>
                                    <i>{{ $shift[$type->title]->title ?? '' }}</i>
                                @if (array_key_exists($type->title,$shift))

						@foreach( $shift[$type->title]->shiftuser as $k =>$u )
                                        {{$u->info->name}}
                                @if ((count($shift[$type->title]->shiftuser)-1) > $k)
                                        <br>
                                @endif
						@endforeach
                                @endif


									</td>

						@endforeach
									<td>
                                <button id="showEnlistment" type="button" data-date={{$i}} onClick="showEnlistment(this)" class="btn btn-primary">
                                  Aanmelden
                                </button>
								@isset($shift)
								<form id="enlist-form_{{$i}}"  method='POST' >
								<div id="E_{{$i}}" style="display:none;">
								<select class="form-control">
						@foreach($shift as $s)
								@isset($s->shifttype)
								<option value="{{$s->id}}">{{$s->shifttype->title}}</value>
								@endisset
						@endforeach
								</select>
								<input type="submit" class="btn btn-warning form-control" value="Verzenden">
								</div>
								</form>
								@endisset
                                    </td>
								</tr>
							@if(array_keys($shifts)[6]==$i)
								<tr>
									<td>&nbsp;</td>
									<td></td>
									<td></td>
									<td></td>
									<td></td>
								</tr>
							@endif
						@endforeach
							</tbody>
						</table>
                    </div>
					<div class="card-footer">
                        <a href="{{
                        $page == 1 ?
                            route('shifts') :
                            route('shifts.page', ['page' => (isset($page) ? $page-1 : -1)])
                    }}" class="pull-left btn">Previous</a>

                        <a href="{{
                        $page == -1 ?
                            route('shifts') :
                            route('shifts.page', ['page' => (isset($page) ? $page+1 : 1)])
                    }}" class="pull-right btn">Next</a>
                        <br class="clearfix"/>
                    </div>
                </div>
            </div>
        </div>
    </div>
@endsection

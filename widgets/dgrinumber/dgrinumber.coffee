class Dashing.Dgrinumber extends Dashing.Widget
  @accessor 'big', Dashing.AnimatedValue

  @accessor 'small', Dashing.AnimatedValue

  @accessor 'isCritical', ->
    @get('big') > 0

  onData: (data) ->
    if data.status
      # clear existing "status-*" classes
      $(@get('node')).attr 'class', (i,c) ->
        c.replace /\bstatus-\S+/g, ''
      # add new class
      $(@get('node')).addClass "status-#{data.status}"